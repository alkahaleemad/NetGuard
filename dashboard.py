import tkinter as tk
from tkinter import ttk, messagebox
import os
import re
import socket
import threading
import requests
import urllib3
from mac_vendor_lookup import MacLookup

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Application Metadata
STUDENT_NAME = "Emad Alkahale"
UNIVERSITY = "Ajman University"
MAJOR = "Security & Network"
PROJECT_VER = "v1.1.0"

class NetworkToolApp:
    def __init__(self, root):
        """Initialize the main GUI application."""
        self.root = root
        self.root.title(f"NetGuard Scanner - {STUDENT_NAME}")
        self.root.geometry("950x750")
        self.root.configure(bg="#1e1e1e")

        # Configure Theme and Colors
        style = ttk.Style()
        style.theme_use('clam')
        
        bg_color = "#1e1e1e"
        fg_color = "#ffffff"
        accent_color = "#00cc66" 
        darker_bg = "#2d2d2d"

        # Widget Styles
        style.configure("TFrame", background=bg_color)
        style.configure("TLabelframe", background=bg_color, foreground=accent_color)
        style.configure("TLabelframe.Label", background=bg_color, foreground=accent_color, font=('Segoe UI', 10, 'bold'))
        style.configure("TLabel", background=bg_color, foreground=fg_color, font=('Segoe UI', 10))
        
        style.configure("TButton", 
                        font=('Segoe UI', 10, 'bold'), 
                        background=darker_bg, 
                        foreground="white",
                        borderwidth=1)
        style.map("TButton", background=[("active", accent_color)])

        style.configure("Treeview", 
                        background=darker_bg, 
                        foreground="white", 
                        fieldbackground=darker_bg,
                        rowheight=30,
                        font=('Segoe UI', 10))
        style.configure("Treeview.Heading", 
                        background="#333333", 
                        foreground="white", 
                        font=('Segoe UI', 11, 'bold'))
        style.map("Treeview", background=[("selected", accent_color)])

        # Build UI Layout
        self._build_header()
        self._build_discovery_section()
        self._build_analysis_section()

        # Initialize Vendor Database
        try:
            self.mac_lookup = MacLookup()
        except:
            pass

    def _build_header(self):
        """Create the top header with the About button."""
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill="x", padx=15, pady=5)

        self.btn_about = ttk.Button(header_frame, text="👤 ABOUT DEVELOPER", command=self.show_about_info)
        self.btn_about.pack(side="right")

    def _build_discovery_section(self):
        """Create the network scanning controls and results table."""
        frame_top = ttk.LabelFrame(self.root, text=" 📡 Network Assets ")
        frame_top.pack(fill="both", expand=True, padx=15, pady=5)

        ctl_frame = ttk.Frame(frame_top)
        ctl_frame.pack(fill="x", padx=5, pady=5)
        
        self.btn_scan = ttk.Button(ctl_frame, text="▶ START SCAN", command=self.start_network_scan)
        self.btn_scan.pack(side="left", padx=5)
        
        self.lbl_status = ttk.Label(ctl_frame, text="Ready to scan...", foreground="#aaaaaa")
        self.lbl_status.pack(side="left", padx=10)

        # Device Table
        columns = ("IP", "MAC", "Vendor")
        self.tree = ttk.Treeview(frame_top, columns=columns, show="headings")
        self.tree.heading("IP", text="IP ADDRESS")
        self.tree.heading("MAC", text="MAC ADDRESS")
        self.tree.heading("Vendor", text="MANUFACTURER")
        
        self.tree.column("IP", width=150, anchor="center")
        self.tree.column("MAC", width=200, anchor="center")
        self.tree.column("Vendor", width=400, anchor="w")
        
        scrollbar = ttk.Scrollbar(frame_top, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)

    def _build_analysis_section(self):
        """Create the detailed analysis and logging section."""
        frame_bottom = ttk.LabelFrame(self.root, text=" 🛡️ Deep Analysis & Security Advice ")
        frame_bottom.pack(fill="both", expand=True, padx=15, pady=10)

        self.btn_port_scan = ttk.Button(frame_bottom, text="TARGET SELECTED DEVICE", command=self.start_port_scan)
        self.btn_port_scan.pack(anchor="w", padx=10, pady=5)

        self.log_area = tk.Text(frame_bottom, height=14, bg="#000000", fg="#00ff00", 
                                font=('Consolas', 10), bd=0, highlightthickness=1, highlightbackground="#333")
        self.log_area.pack(fill="both", expand=True, padx=10, pady=10)

        # Log Text Tags
        self.log_area.tag_config("warning", foreground="yellow")
        self.log_area.tag_config("safe", foreground="#00cc66")

    def show_about_info(self):
        """Display developer credentials."""
        info_text = (
            f"Developer: {STUDENT_NAME}\n"
            f"University: {UNIVERSITY}\n"
            f"Major: {MAJOR}\n\n"
            f"Tool Version: {PROJECT_VER}\n"
            "Description: Professional Network Analysis Tool for Security Research."
        )
        messagebox.showinfo("About Developer", info_text)

    def log(self, msg, tag=None):
        """Append messages to the terminal log."""
        self.log_area.insert(tk.END, msg + "\n", tag)
        self.log_area.see(tk.END)

    def update_status(self, msg):
        self.lbl_status.config(text=msg)

    def start_network_scan(self):
        """Begin the threaded network scan."""
        self.btn_scan.config(state="disabled")
        self.update_status("Scanning network... (This may take 10-20 seconds)")
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        """Execute ARP/Ping sweep to identify active devices."""
        self.log("\n[+] Initiating Network Discovery Protocol...")
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Ping sweep to populate ARP cache
        os.system("for /L %i in (1,1,254) do @start /b ping 192.168.1.%i -n 1 -w 100 > nul")
        
        # Parse ARP table
        output = os.popen("arp -a").read()
        pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})"
        devices = re.findall(pattern, output)
        
        count = 0
        self.log("[*] Resolving MAC Addresses...")
        
        for ip, mac_raw in devices:
            if ip.startswith("2") and int(ip.split('.')[0]) >= 224: continue
            
            mac_clean = mac_raw.replace("-", ":")
            try:
                vendor = self.mac_lookup.lookup(mac_clean)
            except:
                vendor = "Unknown Vendor"

            self.tree.insert("", tk.END, values=(ip, mac_clean, vendor))
            count += 1
            
        self.log(f"[*] Scan Complete. {count} active assets identified.")
        self.update_status(f"Scan Complete. Found {count} devices.")
        self.btn_scan.config(state="normal")

    def start_port_scan(self):
        """Begin threaded port scan on selected target."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Target Error", "Please select a device from the list above.")
            return
        
        item = self.tree.item(selected)
        ip = item['values'][0]
        threading.Thread(target=self.run_deep_scan, args=(ip,), daemon=True).start()

    def run_deep_scan(self, target_ip):
        """Scan common ports and provide security recommendations."""
        self.log(f"\n[+] Starting Vulnerability Assessment: {target_ip}")
        self.log("-" * 60)
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 443, 445, 3306, 3389, 8080]
        open_ports = []
        
        for port in common_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target_ip, port))
            
            if result == 0:
                service_info = ""
                # Attempt banner grab for web services
                if port in [80, 8080, 443]:
                    service_info = self._grab_http_banner(target_ip, port)
                
                self.log(f"   [OPEN] Port {port:<5} {service_info}", "safe")
                
                # Check for security advice
                advice = self._get_security_advice(port)
                if advice:
                    self.log(f"      ⚠️  ADVICE: {advice}", "warning")
                
                open_ports.append(port)
            s.close()
            
        if not open_ports:
            self.log("   [!] No exposed services found (Firewall active).")
        else:
            self.log("-" * 60)
            self.log("[*] Analysis Finished.")

    def _grab_http_banner(self, ip, port):
        """Retrieve HTTP Server header."""
        protocol = "https" if port == 443 else "http"
        try:
            url = f"{protocol}://{ip}:{port}"
            response = requests.get(url, timeout=2, verify=False)
            server = response.headers.get("Server", "Unknown")
            return f"--> Server: {server}"
        except:
            return ""

    def _get_security_advice(self, port):
        """Return security recommendation for a specific port."""
        advice_db = {
            21: "FTP is unencrypted. Use SFTP (Port 22) to prevent password sniffing.",
            22: "SSH is secure, but ensure Root Login is disabled & use Keys instead of passwords.",
            23: "TELNET IS INSECURE (Cleartext). Disable immediately and use SSH.",
            25: "SMTP (Email). Ensure this server is not an Open Relay to prevent spam abuse.",
            53: "DNS. Ensure this is not an Open Resolver to prevent DDoS amplification attacks.",
            80: "HTTP is unencrypted. Configure an automatic redirect to HTTPS (Port 443).",
            443: "HTTPS. Check SSL/TLS certificate validity and disable weak ciphers (e.g., SSLv3).",
            445: "SMB (Windows Sharing). High Risk (WannaCry). Block from internet & patch immediately.",
            3389: "RDP (Remote Desktop). Frequent ransomware target. Use VPN or strong passwords with NLA.",
            3306: "MySQL Database. Do not expose directly to the internet. Bind to localhost only.",
            8080: "Alternative Web Port. Often used for administrative panels. Ensure it is password protected."
        }
        return advice_db.get(port, None)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolApp(root)
    root.mainloop()