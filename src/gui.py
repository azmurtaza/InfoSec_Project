
import customtkinter as ctk
import os
import json
import threading
import time
from tkinter import filedialog
from scanner_engine import MalwareScanner
from quarantine import quarantine_file, delete_quarantined_file, restore_file, sync_quarantine_vault

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

        # --- Sidebar ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="SENTINEL AI", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Navigation Buttons
        self.btn_dashboard = ctk.CTkButton(self.sidebar_frame, text="Dashboard", command=lambda: self.show_frame("dashboard"))
        self.btn_dashboard.grid(row=1, column=0, padx=20, pady=10)
        
        self.btn_scan = ctk.CTkButton(self.sidebar_frame, text="Scan File", command=lambda: self.show_frame("scan"))
        self.btn_scan.grid(row=2, column=0, padx=20, pady=10)

        self.btn_quarantine = ctk.CTkButton(self.sidebar_frame, text="Quarantine", command=lambda: self.show_frame("quarantine"))
        self.btn_quarantine.grid(row=3, column=0, padx=20, pady=10)

        self.btn_settings = ctk.CTkButton(self.sidebar_frame, text="Settings", command=lambda: self.show_frame("settings"))
        self.btn_settings.grid(row=4, column=0, padx=20, pady=10)

        # --- Main Content Area ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        # Create Pages
        self.frames = {}
        for page in ["dashboard", "scan", "quarantine", "settings"]:
            self.frames[page] = ctk.CTkFrame(self.main_frame, fg_color="transparent")
            self.frames[page].grid(row=0, column=0, sticky="nsew")
        
        # Setup Pages
        self.setup_dashboard()
        self.setup_scan()
        self.setup_quarantine()
        self.setup_settings()

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
            self.after(200, self.load_quarantine_list)

    def on_delete(self, entry):
        path = entry.get("original_path")
        if path:
            msg = delete_quarantined_file(path)
            print(msg)
            # Refresh UI
            self.after(200, self.load_quarantine_list)

    # --- Page: Settings ---
    def setup_settings(self):
        frame = self.frames["settings"]
        ctk.CTkLabel(frame, text="Settings", font=ctk.CTkFont(size=24)).pack(pady=20)
        ctk.CTkSwitch(frame, text="Real-time Protection").pack(pady=10)
        ctk.CTkSwitch(frame, text="Cloud Analysis").pack(pady=10)

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
            is_malware = result.get("status") == "malware"
            confidence = result.get("confidence", 0)
            threat_type = result.get("Type", "Malware")
            protocol = result.get("Protocol", "None")
            fname = result.get("file_name", "Unknown")
            
            self.current_threat_path = result.get("file_path")
            self.current_threat_type = threat_type
        else:
            # Fallback
            is_malware = False
            confidence = 0
            fname = "N/A"
            protocol = str(result)
            self.current_threat_path = None

        self.result_card.pack(pady=20, fill="x", padx=50)
        
        if is_malware:
            # Threat Card Styling
            self.result_card.configure(border_color="#ff0000")
            self.lbl_res_title.configure(text=f"THREAT DETECTED", text_color="#ff0000")
            self.lbl_res_file.configure(text=f"File: {fname}")
            self.lbl_res_conf.configure(text=f"Confidence: {confidence:.2f}%")
            
            # New Labels
            self.lbl_res_type.configure(text=f"Detected Type: {threat_type.upper()}")
            self.lbl_res_type.pack(pady=5) # Ensure visible
            
            self.lbl_res_protocol.configure(text=f"Protocol: {protocol}")
            self.lbl_res_protocol.pack(pady=5) # Ensure visible

            self.lbl_res_action.configure(text=f"Action: Quarantine Recommended", text_color="#ffa500") # Orange
            
            # Show Quarantine Button
            self.btn_action_quarantine.pack(pady=10)
            
            # Dashboard Indicator Red
            self.status_canvas.itemconfig(self.status_circle, fill="#ff0000")
            self.lbl_status_text.configure(text="THREAT FOUND", text_color="#ff0000")
            
        else:
            # Safe Card Styling
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

if __name__ == "__main__":
    app = AntivirusApp()
    app.mainloop()
