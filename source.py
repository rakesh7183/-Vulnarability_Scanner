import customtkinter as ctk
import threading
import time
import queue

# --- Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class VulScanX(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("VulScanX - Comprehensive Security Framework")
        self.geometry("1450x900") 
        
        self.gui_queue = queue.Queue()
        self.typewriter_active = False

        # --- Grid Layout ---
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=5) 
        self.grid_columnconfigure(2, weight=3) 

        # ==================== SIDEBAR ====================
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="VulScanX\nFramework", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        self.scan_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Select Scan Scope:", font=ctk.CTkFont(size=12))
        self.scan_mode_label.grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")

        self.scan_type_var = ctk.StringVar(value="Full Stack (Active)")
        self.scan_dropdown = ctk.CTkOptionMenu(
            self.sidebar_frame, 
            values=["Full Stack (Active)", "Passive OSINT"],
            variable=self.scan_type_var,
            command=self.update_scan_button_text
        )
        self.scan_dropdown.grid(row=2, column=0, padx=20, pady=(5, 15))

        self.btn_scan = ctk.CTkButton(
            self.sidebar_frame, 
            text="▶ Run Full Stack Scan", 
            command=self.trigger_scan,
            font=ctk.CTkFont(weight="bold")
        )
        self.btn_scan.grid(row=3, column=0, padx=20, pady=10)

        # ==================== MAIN WORKSPACE ====================
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(2, weight=1) 
        self.main_frame.grid_rowconfigure(3, weight=4) 
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.top_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.top_frame.grid(row=0, column=0, pady=(10, 0), sticky="ew")
        self.top_frame.grid_columnconfigure(0, weight=1)

        self.target_entry = ctk.CTkEntry(self.top_frame, placeholder_text="Enter Target (e.g., 10.0.0.1 or https://example.com)", height=35)
        self.target_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")

        self.status_label = ctk.CTkLabel(self.top_frame, text="Status: IDLE", text_color="#f5d142", font=ctk.CTkFont(weight="bold"))
        self.status_label.grid(row=0, column=1, padx=10)

        self.progress_bar = ctk.CTkProgressBar(self.main_frame, mode="indeterminate")
        self.progress_bar.grid(row=1, column=0, pady=(15, 10), sticky="ew")
        self.progress_bar.set(0)

        self.console_box = ctk.CTkTextbox(self.main_frame, height=120, font=ctk.CTkFont(family="Consolas", size=12))
        self.console_box.grid(row=2, column=0, pady=(0, 10), sticky="nsew")
        self.console_box.insert("0.0", "[*] System Initialized. Network & Web modules loaded.\n")
        self.console_box.configure(state="disabled")

        # --- NEW: Tabbed Interface for separated vectors ---
        self.results_tabview = ctk.CTkTabview(self.main_frame)
        self.results_tabview.grid(row=3, column=0, pady=(0, 10), sticky="nsew")
        
        self.tab_unified = self.results_tabview.add("All Results")
        self.tab_network = self.results_tabview.add("🖥️ Network Vectors")
        self.tab_web = self.results_tabview.add("🌐 Web Vectors")

        self.tables = {}
        for name, tab in zip(["Unified", "Network", "Web"], [self.tab_unified, self.tab_network, self.tab_web]):
            frame = ctk.CTkScrollableFrame(tab, fg_color="transparent")
            frame.pack(expand=True, fill="both")
            frame.grid_columnconfigure((0,1,2,3,4), weight=1)
            self.tables[name] = frame

        # ==================== RIGHT PANEL ====================
        self.right_panel = ctk.CTkFrame(self, fg_color="transparent")
        self.right_panel.grid(row=0, column=2, padx=(0, 20), pady=20, sticky="nsew")
        self.right_panel.grid_rowconfigure(0, weight=1) 
        self.right_panel.grid_rowconfigure(1, weight=2) 
        self.right_panel.grid_columnconfigure(0, weight=1)

        self.recon_frame = ctk.CTkFrame(self.right_panel)
        self.recon_frame.grid(row=0, column=0, pady=(0, 10), sticky="nsew")
        self.recon_frame.grid_columnconfigure(1, weight=1)

        self.recon_header = ctk.CTkLabel(self.recon_frame, text="Service Reconnaissance", font=ctk.CTkFont(size=16, weight="bold"))
        self.recon_header.grid(row=0, column=0, columnspan=2, padx=20, pady=(15, 10), sticky="w")

        self.meta_target_lbl = ctk.CTkLabel(self.recon_frame, text="Target: N/A", font=ctk.CTkFont(size=13))
        self.meta_target_lbl.grid(row=1, column=0, padx=20, pady=2, sticky="w")
        
        self.meta_type_lbl = ctk.CTkLabel(self.recon_frame, text="Scan Mode: N/A", font=ctk.CTkFont(size=13))
        self.meta_type_lbl.grid(row=2, column=0, padx=20, pady=2, sticky="w")
        
        self.meta_os_lbl = ctk.CTkLabel(self.recon_frame, text="Environment: N/A", font=ctk.CTkFont(size=13))
        self.meta_os_lbl.grid(row=3, column=0, padx=20, pady=2, sticky="w")

        self.legend_frame = ctk.CTkFrame(self.recon_frame, fg_color="transparent")
        self.legend_frame.grid(row=4, column=0, columnspan=2, padx=20, pady=(10, 0), sticky="w")
        
        ctk.CTkLabel(self.legend_frame, text="Port Legend: ", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left")
        ctk.CTkLabel(self.legend_frame, text="■ Critical/High ", text_color="#ff4a4a", font=ctk.CTkFont(size=11)).pack(side="left", padx=(5,0))
        ctk.CTkLabel(self.legend_frame, text="■ Cleartext/Info ", text_color="#f5d142", font=ctk.CTkFont(size=11)).pack(side="left", padx=(5,0))
        ctk.CTkLabel(self.legend_frame, text="■ Secure ", text_color="#2ecc71", font=ctk.CTkFont(size=11)).pack(side="left", padx=(5,0))

        self.ports_container = ctk.CTkScrollableFrame(self.recon_frame, fg_color="transparent", height=120)
        self.ports_container.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.current_port_col = 0
        self.current_port_row = 0

        self.details_frame = ctk.CTkFrame(self.right_panel)
        self.details_frame.grid(row=1, column=0, pady=(10, 0), sticky="nsew")
        self.details_frame.grid_rowconfigure(1, weight=1)
        self.details_frame.grid_columnconfigure(0, weight=1)

        self.details_header = ctk.CTkLabel(self.details_frame, text="Intelligence & Protocol Details", font=ctk.CTkFont(size=16, weight="bold"))
        self.details_header.grid(row=0, column=0, padx=20, pady=(15, 5), sticky="w")

        self.details_box = ctk.CTkTextbox(self.details_frame, font=ctk.CTkFont(family="Consolas", size=13), wrap="word")
        self.details_box.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")
        self.details_box.insert("0.0", "Select a port or vulnerability to view specific protocol data and remediation steps.")
        self.details_box.configure(state="disabled")

        self.process_queue()

    # ==================== UI UPDATE LOGIC ====================
    def update_scan_button_text(self, selected_mode):
        mode = "Full Stack Scan" if "Active" in selected_mode else "Passive Scan"
        self.btn_scan.configure(text=f"▶ Run {mode}")

    def process_queue(self):
        try:
            while True:
                msg_type, data = self.gui_queue.get_nowait()
                if msg_type == "log":
                    self.console_box.configure(state="normal")
                    self.console_box.insert("end", f"{data}\n")
                    self.console_box.see("end")
                    self.console_box.configure(state="disabled")
                elif msg_type == "status":
                    self.status_label.configure(text=f"Status: {data[0]}", text_color=data[1])
                elif msg_type == "metadata":
                    self.update_metadata(data)
                elif msg_type == "port":
                    self.animate_port_badge(data)
                elif msg_type == "results":
                    self.process_and_display_results(data)
                elif msg_type == "scan_complete":
                    self.progress_bar.stop()
                    self.btn_scan.configure(state="normal")
                    self.scan_dropdown.configure(state="normal")
        except queue.Empty:
            pass
        finally:
            self.after(50, self.process_queue)

    def update_metadata(self, meta):
        self.meta_target_lbl.configure(text=f"Target: {meta['target']}")
        self.meta_type_lbl.configure(text=f"Scan Mode: {meta['type']}")
        self.meta_os_lbl.configure(text=f"Environment: {meta['os']}")

    def clear_recon_panel(self):
        self.meta_target_lbl.configure(text="Target: N/A")
        self.meta_type_lbl.configure(text="Scan Mode: N/A")
        self.meta_os_lbl.configure(text="Environment: N/A")
        for widget in self.ports_container.winfo_children():
            widget.destroy()
        self.current_port_col = 0
        self.current_port_row = 0

    def animate_port_badge(self, port_data):
        port_num = port_data["port"]
        color = "#2ecc71" 
        if port_data["risk"] == "High":
            color = "#ff4a4a" 
        elif port_data["risk"] == "Medium":
            color = "#f5d142" 

        badge = ctk.CTkButton(
            self.ports_container, 
            text=f"{port_num} ({port_data['service']})", 
            fg_color=color, 
            text_color="gray10",
            hover_color="#ecf0f1",
            corner_radius=5, 
            font=ctk.CTkFont(weight="bold"),
            width=80,
            command=lambda d=port_data: self.trigger_port_details_animation(d)
        )
        badge.grid(row=self.current_port_row, column=self.current_port_col, padx=5, pady=5, sticky="w")
        
        self.current_port_col += 1
        if self.current_port_col > 2:
            self.current_port_col = 0
            self.current_port_row += 1

    def trigger_port_details_animation(self, port_data):
        self.typewriter_active = False
        self.details_box.configure(state="normal")
        self.details_box.delete("0.0", "end")
        self.details_box.configure(state="disabled")
        
        full_text = f"PORT:        {port_data['port']}\n"
        full_text += f"SERVICE:     {port_data['service']}\n"
        full_text += f"STATE:       {port_data['state']}\n"
        full_text += f"RISK LEVEL:  {port_data['risk']}\n"
        full_text += f"{'-'*40}\n\n"
        full_text += f"PROTOCOL DETAILS:\n{port_data['protocol_info']}\n\n"
        full_text += f"KNOWN RISKS:\n{port_data['vulns']}\n"

        self.typewriter_active = True
        self.typewriter_effect(full_text, 0)

    # --- NEW: Data processing and sorting logic ---
    def process_and_display_results(self, raw_data):
        # 1. Sort data by Severity Level
        severity_hierarchy = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
        sorted_data = sorted(raw_data, key=lambda x: severity_hierarchy.get(x["severity"], 99))

        # 2. Separate data into distinct vectors
        network_data = [d for d in sorted_data if d["vector"] == "Network"]
        web_data = [d for d in sorted_data if d["vector"] == "Web"]

        # 3. Animate each tab
        self.animate_table_rows(self.tables["Unified"], sorted_data, 0)
        self.animate_table_rows(self.tables["Network"], network_data, 0)
        self.animate_table_rows(self.tables["Web"], web_data, 0)

    def setup_table_headers(self):
        headers = ["Severity", "Vector", "Category", "Vulnerability", "Action"]
        for frame in self.tables.values():
            for widget in frame.winfo_children():
                widget.destroy()
            for col, text in enumerate(headers):
                lbl = ctk.CTkLabel(frame, text=text, font=ctk.CTkFont(weight="bold", size=14))
                lbl.grid(row=0, column=col, sticky="w", padx=10, pady=(5, 10))

    def animate_table_rows(self, target_frame, data, current_row=0):
        if current_row < len(data):
            row_data = data[current_row]
            colors = {"CRITICAL": "#ff4a4a", "HIGH": "#ff8c4a", "MEDIUM": "#f5d142", "LOW": "#2ecc71", "INFO": "#4a90e2"}
            text_color = colors.get(row_data["severity"], "white")

            vector_text = f"🌐 {row_data['vector']}" if row_data['vector'] == "Web" else f"🖥️ {row_data['vector']}"

            ctk.CTkLabel(target_frame, text=row_data["severity"], text_color=text_color).grid(row=current_row + 1, column=0, sticky="w", padx=10, pady=5)
            ctk.CTkLabel(target_frame, text=vector_text).grid(row=current_row + 1, column=1, sticky="w", padx=10, pady=5)
            ctk.CTkLabel(target_frame, text=row_data["category"]).grid(row=current_row + 1, column=2, sticky="w", padx=10, pady=5)
            ctk.CTkLabel(target_frame, text=row_data["short_name"]).grid(row=current_row + 1, column=3, sticky="w", padx=10, pady=5)
            
            btn = ctk.CTkButton(target_frame, text="View Details", width=90, height=24, command=lambda d=row_data: self.trigger_vulnerability_animation(d))
            btn.grid(row=current_row + 1, column=4, sticky="w", padx=10, pady=5)
            
            self.after(20, self.animate_table_rows, target_frame, data, current_row + 1)

    def trigger_vulnerability_animation(self, data):
        self.typewriter_active = False
        self.details_box.configure(state="normal")
        self.details_box.delete("0.0", "end")
        self.details_box.configure(state="disabled")
        
        full_text = f"[{data['severity']}] {data['short_name']}\n"
        full_text += f"{'='*40}\n\n"
        full_text += f"VECTOR:      {data['vector']} Architecture\n"
        full_text += f"CATEGORY:    {data['category']}\n"
        full_text += f"CVSS SCORE:  {data.get('cvss', 'N/A')}\n\n"
        full_text += f"DESCRIPTION:\n{data['description']}\n\n"
        full_text += f"REMEDIATION:\n{data['remediation']}\n"

        self.typewriter_active = True
        self.typewriter_effect(full_text, 0)

    def typewriter_effect(self, text, index):
        if self.typewriter_active and index < len(text):
            self.details_box.configure(state="normal")
            self.details_box.insert("end", text[index])
            self.details_box.see("end")
            self.details_box.configure(state="disabled")
            self.after(8, self.typewriter_effect, text, index + 1)

    # ==================== BACKEND SCANNING ENGINE ====================
    def trigger_scan(self):
        scan_type = self.scan_type_var.get() 
        target = self.target_entry.get()
        
        if not target:
            self.gui_queue.put(("log", "[!] Error: Target is required."))
            return

        self.btn_scan.configure(state="disabled")
        self.scan_dropdown.configure(state="disabled")
        self.progress_bar.start()
        
        self.clear_recon_panel()
        self.setup_table_headers()
        self.details_box.configure(state="normal")
        self.details_box.delete("0.0", "end")
        self.details_box.configure(state="disabled")
        
        scan_thread = threading.Thread(target=self.execute_scan_logic, args=(scan_type, target), daemon=True)
        scan_thread.start()

    def execute_scan_logic(self, scan_type, target):
        self.gui_queue.put(("status", ("SCAN IN PROGRESS", "#ff8c4a")))
        
        detected_env = "Linux Server (Ubuntu) / Apache" if "Active" in scan_type else "Unknown"
        self.gui_queue.put(("metadata", {"target": target, "type": scan_type, "os": detected_env}))

        try:
            if "Active" in scan_type:
                self.gui_queue.put(("log", f"[*] Running Network Infrastructure Scan on {target}..."))
                
                network_ports = [
                    {"port": "21/tcp", "service": "FTP", "state": "Open", "risk": "High", "protocol_info": "File Transfer Protocol used for bulk file transfers. Runs entirely in plaintext.", "vulns": "• Anonymous login allowed\n• Cleartext credential sniffing"},
                    {"port": "22/tcp", "service": "SSH", "state": "Open", "risk": "Low", "protocol_info": "Secure Shell provides encrypted remote administration.", "vulns": "• User Enumeration possible on older versions"},
                    {"port": "23/tcp", "service": "Telnet", "state": "Open", "risk": "High", "protocol_info": "Legacy remote administration protocol. Sends all keystrokes unencrypted.", "vulns": "• Highly susceptible to Man-in-the-Middle (MitM) attacks"},
                    {"port": "80/tcp", "service": "HTTP", "state": "Open", "risk": "Medium", "protocol_info": "Standard unencrypted web traffic.", "vulns": "• Missing HSTS\n• Exposes web attack surface"},
                    {"port": "443/tcp", "service": "HTTPS", "state": "Open", "risk": "Low", "protocol_info": "Encrypted web traffic using TLS.", "vulns": "• Weak Cipher Suites (e.g., TLS 1.0 enabled)"},
                    {"port": "445/tcp", "service": "SMB", "state": "Open", "risk": "High", "protocol_info": "Server Message Block for file sharing and printer access.", "vulns": "• SMBv1 Enabled (EternalBlue risk)"},
                    {"port": "3389/tcp", "service": "RDP", "state": "Open", "risk": "High", "protocol_info": "Remote Desktop Protocol for Windows GUI remote access.", "vulns": "• Brute-force target\n• BlueKeep vulnerability"}
                ]

                for port_data in network_ports:
                    time.sleep(0.3) 
                    self.gui_queue.put(("log", f"[+] Network module found port: {port_data['port']}"))
                    self.gui_queue.put(("port", port_data))

                self.gui_queue.put(("log", f"[*] Spawning Web Application Scanner against port 80/443..."))
                
                web_services = ["/api/v1/", "/login.php", "/admin/dashboard", "/.git/config", "/images?file="]
                for service in web_services:
                    time.sleep(0.3)
                    self.gui_queue.put(("log", f"[+] Web module discovered endpoint: {service}"))
                    self.gui_queue.put(("port", {"port": "Web", "service": service, "state": "Accessible", "risk": "Medium" if "images" in service else "High", "protocol_info": f"Web Directory/Endpoint: {service}", "vulns": "Analyzed by application scanner."}))

                self.gui_queue.put(("log", "[*] Discovery complete. Correlating vulnerabilities..."))
                time.sleep(1.0)
                
                # I intentionally jumbled the severities here so you can see the sorting algorithm work!
                results = [
                    {
                        "severity": "LOW", "vector": "Web", "category": "Misconfiguration", "short_name": "Missing Strict-Transport-Security",
                        "cvss": "3.1 (Low)", "description": "The web server response is missing the HTTP Strict Transport Security (HSTS) header.",
                        "remediation": "Configure the web server to append the 'Strict-Transport-Security' header to all HTTPS responses."
                    },
                    {
                        "severity": "HIGH", "vector": "Network", "category": "Cleartext Protocol", "short_name": "Telnet Enabled",
                        "cvss": "7.5 (High)", "description": "Port 23 is running Telnet. All traffic, including administrator passwords, is transmitted in plaintext.",
                        "remediation": "Disable the Telnet service and replace it with SSH (Port 22)."
                    },
                    {
                        "severity": "CRITICAL", "vector": "Web", "category": "Injection", "short_name": "SQL Injection on /login.php",
                        "cvss": "9.0 (Critical)", "description": "The 'username' parameter in the web login form does not sanitize input, allowing boolean-based SQL injection.",
                        "remediation": "Rewrite database queries using Prepared Statements."
                    },
                    {
                        "severity": "CRITICAL", "vector": "Network", "category": "RCE", "short_name": "SMBv1 Enabled (EternalBlue)",
                        "cvss": "9.8 (Critical)", "description": "The server is running SMBv1, which is vulnerable to the MS17-010 (EternalBlue) remote code execution flaw.",
                        "remediation": "Disable SMBv1 immediately and apply the MS17-010 security patch."
                    },
                    {
                        "severity": "MEDIUM", "vector": "Network", "category": "Outdated Service", "short_name": "Vulnerable OpenSSH Version",
                        "cvss": "5.3 (Medium)", "description": "Port 22 is running OpenSSH 7.2p2, which is vulnerable to user enumeration.",
                        "remediation": "Update OpenSSH to the latest stable release."
                    },
                    {
                        "severity": "CRITICAL", "vector": "Web", "category": "Information Leak", "short_name": "Exposed .git Repository",
                        "cvss": "9.1 (Critical)", "description": "A valid .git repository was found at '/.git/'.",
                        "remediation": "Configure the web server to return a 403 Forbidden status for all requests to /.git/."
                    }
                ]
            else:
                self.gui_queue.put(("log", f"[*] Fetching passive network footprints for {target}..."))
                time.sleep(1.5)
                results = []

            self.gui_queue.put(("results", results))
            self.gui_queue.put(("status", ("SCAN COMPLETE", "#4a90e2")))

        except Exception as e:
            self.gui_queue.put(("log", f"[!] System Error: {e}"))
            self.gui_queue.put(("status", ("ERROR", "#ff4a4a")))
        finally:
            self.gui_queue.put(("scan_complete", None))

if __name__ == "__main__":
    app = VulScanX()
    app.mainloop()