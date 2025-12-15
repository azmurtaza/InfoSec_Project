
import customtkinter as ctk
import os
import json
import threading
import time
from tkinter import filedialog
from scanner_engine import MalwareScanner
from quarantine import quarantine_file, delete_quarantined_file, restore_file, sync_quarantine_vault
from realtime_protection import RealTimeProtector

# --- Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")  # Cyber Blue-ish

class AntivirusApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("AI Antivirus - Sentinel")
        self.geometry("900x600")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Initialize Logic
        self.scanner = MalwareScanner()
        self.scan_thread = None
        self.current_threat_path = None
        self.current_threat_type = "Generic"
        
        # Real-time Protection
        self.protector = RealTimeProtector(self.on_realtime_threat_detected, self.scanner)

        # --- Sidebar ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        # self.sidebar_frame.grid_rowconfigure(5, weight=1) # Removed to fix alignment

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="SENTINEL AI", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Navigation Buttons
        # Navigation Buttons
        self.btn_dashboard = ctk.CTkButton(self.sidebar_frame, text="Dashboard", command=lambda: self.show_frame("dashboard"))
        self.btn_dashboard.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_scan = ctk.CTkButton(self.sidebar_frame, text="Scan File", command=lambda: self.show_frame("scan"))
        self.btn_scan.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.btn_quarantine = ctk.CTkButton(self.sidebar_frame, text="Quarantine", command=lambda: self.show_frame("quarantine"))
        self.btn_quarantine.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_realtime = ctk.CTkButton(self.sidebar_frame, text="Realtime", command=lambda: self.show_frame("realtime"))
        self.btn_realtime.grid(row=4, column=0, padx=20, pady=10, sticky="ew")

        self.btn_quick = ctk.CTkButton(self.sidebar_frame, text="Quick Scan", command=lambda: self.show_frame("quick"))
        self.btn_quick.grid(row=5, column=0, padx=20, pady=10, sticky="ew")
        
        # Grid Fix: Settings was at row 6, which is fine, but let's be explicit
        self.btn_settings = ctk.CTkButton(self.sidebar_frame, text="Settings", command=lambda: self.show_frame("settings"))
        self.btn_settings.grid(row=6, column=0, padx=20, pady=10, sticky="ew")

        # --- Main Content Area ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        # Create Pages
        self.frames = {}
        # Create Pages
        self.frames = {}
        for page in ["dashboard", "scan", "quarantine", "settings", "realtime", "quick"]:
            self.frames[page] = ctk.CTkFrame(self.main_frame, fg_color="transparent")
            self.frames[page].grid(row=0, column=0, sticky="nsew")
        
        # Setup Pages
        self.setup_dashboard()
        self.setup_scan()
        self.setup_quarantine()
        self.setup_settings()
        self.setup_realtime()
        self.setup_quick_scan()

        # Start on Dashboard
        self.show_frame("dashboard")

    def show_frame(self, name):
        # Hide all, show one
        for frame in self.frames.values():
            frame.grid_forget()
        self.frames[name].grid(row=0, column=0, sticky="nsew")

    # --- Page: Dashboard ---
    def setup_dashboard(self):
        frame = self.frames["dashboard"]
        
        lbl_title = ctk.CTkLabel(frame, text="System Status", font=ctk.CTkFont(size=24, weight="bold"))
        lbl_title.pack(pady=20)

        # Status Indicator (Big Circle)
        self.status_canvas = ctk.CTkCanvas(frame, width=200, height=200, bg="#2b2b2b", highlightthickness=0)
        self.status_canvas.pack(pady=20)
        
        # Draw initial Green Circle
        self.status_circle = self.status_canvas.create_oval(20, 20, 180, 180, fill="#00ff00", outline="")
        
        self.lbl_status_text = ctk.CTkLabel(frame, text="SYSTEM SECURE", font=ctk.CTkFont(size=18, weight="bold"), text_color="#00ff00")
        self.lbl_status_text.pack(pady=10)
        
        lbl_info = ctk.CTkLabel(frame, text="Real-time protection is active.\nAI Model loaded and ready.", font=ctk.CTkFont(size=14))
        lbl_info.pack(pady=10)

    # --- Page: Scan ---
    def setup_scan(self):
        frame = self.frames["scan"]
        
        lbl_title = ctk.CTkLabel(frame, text="Deep Scan", font=ctk.CTkFont(size=24, weight="bold"))
        lbl_title.pack(pady=20)

        # File Drop Area / Browse
        self.btn_browse = ctk.CTkButton(frame, text="Browse Data File (.exe, .dll)", height=50, width=200, font=ctk.CTkFont(size=16), command=self.browse_file)
        self.btn_browse.pack(pady=40)

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(frame, width=400)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=20)
        self.progress_bar.pack_forget() # Hide initially

        # Result Card (Threat Card)
        self.result_card = ctk.CTkFrame(frame, corner_radius=10, border_width=2, border_color="#555")
        self.result_card.pack(pady=20, fill="x", padx=50)
        self.result_card.pack_forget() # Hide initially

        self.lbl_res_title = ctk.CTkLabel(self.result_card, text="Scan Result", font=ctk.CTkFont(size=18, weight="bold"))
        self.lbl_res_title.pack(pady=10)
        
        self.lbl_res_file = ctk.CTkLabel(self.result_card, text="File: ...")
        self.lbl_res_file.pack(pady=5)
        
        self.lbl_res_conf = ctk.CTkLabel(self.result_card, text="Confidence: ...")
        self.lbl_res_conf.pack(pady=5)

        # New Labels for Type and Protocol
        self.lbl_res_type = ctk.CTkLabel(self.result_card, text="Type: ...", font=ctk.CTkFont(size=16, weight="bold"), text_color="#ffff00")
        self.lbl_res_type.pack(pady=5)
        
        self.lbl_res_protocol = ctk.CTkLabel(self.result_card, text="Protocol: ...")
        self.lbl_res_protocol.pack(pady=5)
        
        self.lbl_res_action = ctk.CTkLabel(self.result_card, text="Suggested Action: ...")
        self.lbl_res_action.pack(pady=10)
        
        # Action Buttons specific to result
        self.btn_action_quarantine = ctk.CTkButton(self.result_card, text="MOVE TO QUARANTINE", fg_color="red", hover_color="darkred", command=self.action_quarantine)
        self.btn_action_quarantine.pack(pady=10)
        self.btn_action_quarantine.pack_forget() # Hide initially

    # --- Page: Quarantine ---
    def setup_quarantine(self):
        frame = self.frames["quarantine"]
        
        # Header
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(header, text="Quarantine Vault", font=ctk.CTkFont(size=24, weight="bold")).pack(side="left")
        ctk.CTkButton(header, text="Refresh", width=100, command=self.load_quarantine_list).pack(side="right")
        
        ctk.CTkLabel(frame, text="Secure Storage for Locked Threats").pack(pady=(0, 10))

        # List Area
        self.quarantine_list = ctk.CTkScrollableFrame(frame, width=800, height=400)
        self.quarantine_list.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Load initial data
        self.load_quarantine_list()


    def load_quarantine_list(self):
        # 1. Sync first to find any locked files not in logs (like eicar.exe)
        sync_quarantine_vault()

        # Clear existing
        for widget in self.quarantine_list.winfo_children():
            widget.destroy()

        # Path to log
        log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "quarantine.json")
        
        if not os.path.exists(log_path):
            ctk.CTkLabel(self.quarantine_list, text="No quarantined items found.").pack(pady=20)
            return

        try:
            with open(log_path, 'r') as f:
                logs = json.load(f)
                
            # Filter: Only show active "Quarantined" items
            active_logs = [e for e in logs if e.get('status') == "Quarantined"]

            if not active_logs:
                ctk.CTkLabel(self.quarantine_list, text="Vault is empty (No active threats).").pack(pady=20)
                return

            # Display entries (Newest first)
            for entry in reversed(active_logs):
                self.create_quarantine_item(entry)
                
        except Exception as e:
            ctk.CTkLabel(self.quarantine_list, text=f"Error loading vault: {e}").pack(pady=20)

    def create_quarantine_item(self, entry):
        item = ctk.CTkFrame(self.quarantine_list, fg_color="#333", corner_radius=10)
        item.pack(fill="x", pady=5, padx=5)
        
        # Left: Icon/Type
        type_lbl = ctk.CTkLabel(item, text="☣", font=ctk.CTkFont(size=24))
        type_lbl.pack(side="left", padx=15, pady=10)
        
        # Middle: Details
        details = ctk.CTkFrame(item, fg_color="transparent")
        details.pack(side="left", fill="both", expand=True, padx=10)
        
        orig_path = entry.get("original_path", "Unknown")
        fname = os.path.basename(orig_path)
        timestamp = entry.get("timestamp", "").replace("T", " ")[:19]
        threat = entry.get("threat_type", "Unknown Threat")
        
        ctk.CTkLabel(details, text=fname, font=ctk.CTkFont(size=14, weight="bold"), anchor="w").pack(fill="x")
        ctk.CTkLabel(details, text=f"{threat} | {timestamp}", font=ctk.CTkFont(size=12), text_color="#aaa", anchor="w").pack(fill="x")
        
        # Right: Action Buttons
        actions_frame = ctk.CTkFrame(item, fg_color="transparent")
        actions_frame.pack(side="right", padx=10)
        
        status = entry.get("status", "Quarantined")
        
        if status == "Quarantined":
            ctk.CTkButton(actions_frame, text="Unlock", fg_color="green", width=60, 
                          command=lambda e=entry: self.on_restore(e)).pack(side="left", padx=5)
            
            ctk.CTkButton(actions_frame, text="Delete", fg_color="darkred", width=60, 
                          command=lambda e=entry: self.on_delete(e)).pack(side="left", padx=5)
        else:
            # Just show status if already handled (Restored/Deleted)
            ctk.CTkLabel(actions_frame, text=status.upper(), text_color="#888", font=ctk.CTkFont(weight="bold")).pack(side="right", padx=10)

    def on_restore(self, entry):
        path = entry.get("original_path")
        if path:
            msg = restore_file(path)
            print(msg) # For debug
            # Refresh UI
            # Refresh UI
            self.after(200, self.load_quarantine_list)
            # Sync Fix: Check if we need to clear the Scan page
            if self.current_threat_path and path and os.path.normpath(path) == os.path.normpath(self.current_threat_path):
                self.clear_scan_result()

    def on_delete(self, entry):
        path = entry.get("original_path")
        if path:
            msg = delete_quarantined_file(path)
            print(msg)
            # Refresh UI
            # Refresh UI
            self.after(200, self.load_quarantine_list)
            # Sync Fix: Check if we need to clear the Scan page
            if self.current_threat_path and path and os.path.normpath(path) == os.path.normpath(self.current_threat_path):
                self.clear_scan_result()

    def clear_scan_result(self):
        # Reset Scan Page UI
        self.result_card.pack_forget()
        self.current_threat_path = None
        self.btn_browse.configure(state="normal")
        self.lbl_status_text.configure(text="SYSTEM SECURE", text_color="#00ff00")
        self.status_canvas.itemconfig(self.status_circle, fill="#00ff00")

    # --- Page: Settings ---
    def setup_settings(self):
        frame = self.frames["settings"]
        ctk.CTkLabel(frame, text="Settings", font=ctk.CTkFont(size=24)).pack(pady=20)
        ctk.CTkLabel(frame, text="General Settings").pack(pady=10)
        
        self.sw_notify = ctk.CTkSwitch(frame, text="Notifications")
        self.sw_notify.select() # Default On
        self.sw_notify.pack(pady=10)
        
        self.sw_auto_q = ctk.CTkSwitch(frame, text="Auto-Quarantine High Threats")
        self.sw_auto_q.pack(pady=10)
        
        ctk.CTkLabel(frame, text="Theme").pack(pady=(20, 5))
        self.opt_theme = ctk.CTkOptionMenu(frame, values=["Dark", "Light"], command=self.change_theme)
        self.opt_theme.set("Dark")
        self.opt_theme.pack(pady=5)
        
    def change_theme(self, new_theme):
        ctk.set_appearance_mode(new_theme)

    # --- Page: Realtime ---
    def setup_realtime(self):
        frame = self.frames["realtime"]
        ctk.CTkLabel(frame, text="Real-time Protection", font=ctk.CTkFont(size=24)).pack(pady=20)
        
        # Status Icon
        self.rt_status_canvas = ctk.CTkCanvas(frame, width=150, height=150, bg="#2b2b2b", highlightthickness=0)
        self.rt_status_canvas.pack(pady=20)
        self.rt_status_circle = self.rt_status_canvas.create_oval(15, 15, 135, 135, fill="#555", outline="")
        
        self.lbl_rt_status = ctk.CTkLabel(frame, text="PROTECTION OFF", font=ctk.CTkFont(size=18, weight="bold"), text_color="#aaa")
        self.lbl_rt_status.pack(pady=10)
        
        self.sw_realtime = ctk.CTkSwitch(frame, text="Enable Real-time Protection", command=self.toggle_realtime, font=ctk.CTkFont(size=16))
        self.sw_realtime.pack(pady=20)
        
        ctk.CTkLabel(frame, text="Monitored Folder: Downloads", text_color="#888").pack(pady=5)

    # --- Page: Quick Scan ---
    def setup_quick_scan(self):
        frame = self.frames["quick"]
        ctk.CTkLabel(frame, text="Custom Scan", font=ctk.CTkFont(size=24)).pack(pady=20)
        ctk.CTkLabel(frame, text="Select a folder to scan recursively for threats.", text_color="#aaa").pack(pady=(0, 20))
        
        # Folder Selection
        self.selected_folder_path = None
        self.btn_select_folder = ctk.CTkButton(frame, text="Select Folder", height=40, font=ctk.CTkFont(size=14), command=self.select_scan_folder)
        self.btn_select_folder.pack(pady=10)
        
        self.lbl_selected_folder = ctk.CTkLabel(frame, text="No folder selected", text_color="gray")
        self.lbl_selected_folder.pack(pady=5)

        self.btn_start_quick = ctk.CTkButton(frame, text="Start Scan", height=50, width=200, font=ctk.CTkFont(size=16), command=self.start_quick_scan)
        self.btn_start_quick.pack(pady=20)
        
        self.quick_progress = ctk.CTkProgressBar(frame, width=400)
        self.quick_progress.set(0)
        self.quick_progress.pack(pady=20)
        self.quick_progress.pack_forget()
        
        self.lbl_quick_status = ctk.CTkLabel(frame, text="Ready to scan.")
        self.lbl_quick_status.pack(pady=10)
        
        # Results List
        self.quick_results_frame = ctk.CTkScrollableFrame(frame, width=700, height=300, label_text="Threats Found")
        self.quick_results_frame.pack(pady=10, fill="both", expand=True)

    def select_scan_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.selected_folder_path = folder_selected
            self.lbl_selected_folder.configure(text=f"Selected: {self.selected_folder_path}", text_color="white")
            self.lbl_quick_status.configure(text="Ready to scan.")

    def start_quick_scan(self):
        if not self.selected_folder_path:
             self.lbl_quick_status.configure(text="Please select a folder first!", text_color="orange")
             return

        self.btn_start_quick.configure(state="disabled")
        self.btn_select_folder.configure(state="disabled")
        
        self.quick_progress.pack(pady=20)
        self.quick_progress.start()
        self.lbl_quick_status.configure(text=f"Scanning {os.path.basename(self.selected_folder_path)}...", text_color="white")
        
        # Clear previous results
        for widget in self.quick_results_frame.winfo_children():
            widget.destroy()
            
        threading.Thread(target=self.run_quick_scan_logic).start()

    def run_quick_scan_logic(self):
        target = self.selected_folder_path
        threats = []
        
        # Basic progress update
        self.after(0, lambda: self.lbl_quick_status.configure(text=f"Scanning {target}..."))
        
        try:
            for result in self.scanner.scan_directory(target):
                threats.append(result)
        except Exception as e:
            print(f"Error checking directory: {e}")
        
        self.after(0, lambda: self.finish_quick_scan(threats))

    def finish_quick_scan(self, threats):
        self.quick_progress.stop()
        self.quick_progress.pack_forget()
        self.btn_start_quick.configure(state="normal")
        self.btn_select_folder.configure(state="normal")
        
        if not threats:
            self.lbl_quick_status.configure(text="Scan Complete. No threats found!")
            ctk.CTkLabel(self.quick_results_frame, text="No threats found. System is clean.", text_color="green").pack(pady=20)
        else:
            self.lbl_quick_status.configure(text=f"Scan Complete. {len(threats)} threats found!")
            for threat in threats:
                self.add_quick_result_item(threat)

    def add_quick_result_item(self, threat):
         item = ctk.CTkFrame(self.quick_results_frame)
         item.pack(fill="x", pady=2)
         ctk.CTkLabel(item, text=f"⚠️ {os.path.basename(threat['file_path'])}", text_color="red", anchor="w").pack(side="left", padx=10)
         ctk.CTkLabel(item, text=threat.get('Type', 'Unknown'), anchor="w").pack(side="left", padx=10)
         
         # Quarantine button for this item
         # Note: This is a simplified action, ideally we'd want to refresh the list after action
         ctk.CTkButton(item, text="Quarantine", width=80, fg_color="red", 
                       command=lambda p=threat['file_path'], t=threat.get('Type', 'Generic'): self.quick_quarantine(p, t, item)).pack(side="right", padx=5)

    def quick_quarantine(self, path, threat_type, widget):
        res = quarantine_file(path, threat_type)
        print(res)
        widget.destroy()

    # --- Logic ---
    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Executables", "*.exe"), ("DLLs", "*.dll"), ("All Files", "*.*")])
        if file_path:
            self.start_scan(file_path)

    def start_scan(self, file_path):
        # Reset UI
        self.result_card.pack_forget()
        self.progress_bar.pack(pady=20)
        self.progress_bar.set(0)
        self.btn_browse.configure(state="disabled")
        
        # Start Thread
        self.scan_thread = threading.Thread(target=self.run_scan_logic, args=(file_path,))
        self.scan_thread.start()
        
        # Animate progress bar while thinking
        self.animate_progress()

    def animate_progress(self):
        # Simple fake animation loop that stops when thread is done
        if self.scan_thread and self.scan_thread.is_alive():
            current = self.progress_bar.get()
            if current < 0.9:
                self.progress_bar.set(current + 0.05)
            self.after(100, self.animate_progress)
        else:
            self.progress_bar.set(1.0)
            self.btn_browse.configure(state="normal")

    def run_scan_logic(self, file_path):
        # Actual Heavy Lifting
        time.sleep(1.0) # UX Delay
        result = self.scanner.scan_file(file_path)
        
        # Schedule UI update
        self.after(0, lambda: self.display_result(result))

    def display_result(self, result):
        # Verify structure
        if isinstance(result, dict):
            status = result.get("status", "benign")
            is_malware = status == "malware"
            is_suspicious = status == "suspicious"
            confidence = result.get("confidence", 0)
            threat_type = result.get("Type", "Malware")
            protocol = result.get("Protocol", "None")
            fname = result.get("file_name", "Unknown")
            
            self.current_threat_path = result.get("file_path")
            self.current_threat_type = threat_type
        else:
            # Fallback
            is_malware = False
            is_suspicious = False
            confidence = 0
            fname = "N/A"
            protocol = str(result)
            self.current_threat_path = None

        self.result_card.pack(pady=20, fill="x", padx=50)
        
        if is_malware:
            # Malware Card Styling (RED)
            self.result_card.configure(border_color="#ff0000")
            self.lbl_res_title.configure(text=f"THREAT DETECTED", text_color="#ff0000")
            self.lbl_res_file.configure(text=f"File: {fname}")
            self.lbl_res_conf.configure(text=f"Confidence: {confidence:.2f}%")
            
            # New Labels
            self.lbl_res_type.configure(text=f"Detected Type: {threat_type.upper()}")
            self.lbl_res_type.pack(pady=5)
            
            self.lbl_res_protocol.configure(text=f"Protocol: {protocol}")
            self.lbl_res_protocol.pack(pady=5)

            self.lbl_res_action.configure(text=f"Action: Quarantine Recommended", text_color="#ffa500")
            
            # Show Quarantine Button
            self.btn_action_quarantine.pack(pady=10)
            
            # Dashboard Indicator Red
            self.status_canvas.itemconfig(self.status_circle, fill="#ff0000")
            self.lbl_status_text.configure(text="THREAT FOUND", text_color="#ff0000")
            
        elif is_suspicious:
            # Suspicious Card Styling (YELLOW/ORANGE)
            self.result_card.configure(border_color="#ffaa00")
            self.lbl_res_title.configure(text="SUSPICIOUS FILE", text_color="#ffaa00")
            self.lbl_res_file.configure(text=f"File: {fname}")
            self.lbl_res_conf.configure(text=f"Confidence: {confidence:.2f}% (Medium)")
            
            # Show type info
            self.lbl_res_type.configure(text=f"Status: Requires Review")
            self.lbl_res_type.pack(pady=5)
            
            self.lbl_res_protocol.configure(text=f"Recommendation: Manual inspection advised")
            self.lbl_res_protocol.pack(pady=5)

            self.lbl_res_action.configure(text="Action: Review file manually or quarantine if unsure", text_color="#ffaa00")
            
            # Show Quarantine Button for suspicious files too
            self.btn_action_quarantine.pack(pady=10)
            
            # Dashboard Indicator Yellow
            self.status_canvas.itemconfig(self.status_circle, fill="#ffaa00")
            self.lbl_status_text.configure(text="SUSPICIOUS FILE", text_color="#ffaa00")
            
        else:
            # Safe Card Styling (GREEN)
            self.result_card.configure(border_color="#00ff00")
            self.lbl_res_title.configure(text="Clean File", text_color="#00ff00")
            self.lbl_res_file.configure(text=f"File: {fname}")
            self.lbl_res_conf.configure(text=f"Confidence: {confidence:.2f}% (Benign)")
            
            # Hide Threat details
            self.lbl_res_type.pack_forget()
            self.lbl_res_protocol.pack_forget()
            
            self.lbl_res_action.configure(text="System is safe.", text_color="#ddd")
            
            # Hide Quarantine Button
            self.btn_action_quarantine.pack_forget()

            # Dashboard Indicator Green
            self.status_canvas.itemconfig(self.status_circle, fill="#00ff00")
            self.lbl_status_text.configure(text="SYSTEM SECURE", text_color="#00ff00")

    def action_quarantine(self):
        if self.current_threat_path:
            res = quarantine_file(self.current_threat_path, self.current_threat_type)
            # Update UI to show success
            self.lbl_res_action.configure(text=str(res), text_color="#00ff00")
            self.btn_action_quarantine.pack_forget()
            
            # Set status to yellow/handled
            self.status_canvas.itemconfig(self.status_circle, fill="#ffff00")
            self.lbl_status_text.configure(text="THREAT QUARANTINED", text_color="#ffff00")
            
            # Sync Fix: Hide the card too or show success message?
            # User asked: "Thread Detected" and "Move to Quarantine" button should also disappear
            self.result_card.pack_forget()
            self.current_threat_path = None

    def toggle_realtime(self):
        if self.sw_realtime.get() == 1:
            self.protector.start()
            self.lbl_rt_status.configure(text="PROTECTING", text_color="#00ff00")
            self.rt_status_canvas.itemconfig(self.rt_status_circle, fill="#00ff00")
        else:
            self.protector.stop()
            self.lbl_rt_status.configure(text="PROTECTION OFF", text_color="#aaa")
            self.rt_status_canvas.itemconfig(self.rt_status_circle, fill="#555")

    def on_realtime_threat_detected(self, result):
        # Callback from background thread, must use after to be thread-safe
        self.after(0, lambda: self._handle_realtime_alert(result))

    def _handle_realtime_alert(self, result):
        # Force switch to dashboard or show a popup
        self.show_frame("dashboard")
        
        fname = result.get("file_name", "Unknown")
        threat_type = result.get("Type", "Unknown")
        
        self.status_canvas.itemconfig(self.status_circle, fill="#ff0000")
        self.lbl_status_text.configure(text=f"REAL-TIME THREAT: {fname}", text_color="#ff0000")
        
        # Also maybe pop up the scan result to show details?
        # For now, let's just log it or maybe redirect to scan page with results
        self.display_result(result)
        self.show_frame("scan") # Show the details

if __name__ == "__main__":
    app = AntivirusApp()
    app.mainloop()
