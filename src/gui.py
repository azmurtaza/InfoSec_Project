
import customtkinter as ctk
import os
import json
import threading
import time
from tkinter import filedialog
from scanner_engine import MalwareScanner
from quarantine import quarantine_file, delete_quarantined_file, restore_file, sync_quarantine_vault
from realtime_protection import RealTimeProtector
from datetime import datetime

# --- Cybersecurity Theme Configuration ---
ctk.set_appearance_mode("Dark")

# Custom Color Palette (Dark Mode Only)
COLORS = {
    "bg_primary": "#1a1a1a",      # Deep Cyber-Dark
    "bg_secondary": "#2b2b2b",    # Card/Panel
    "accent": "#2cc5f6",          # Cyber Blue
    "success": "#00ff9d",         # Neon Green
    "danger": "#ff2e2e",          # Alert Red
    "warning": "#ffaa00",         # Caution Yellow
    "text_primary": "#ffffff",
    "text_secondary": "#aaaaaa",
    "border": "#555555"
}

class AntivirusApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("SENTINEL AI - Advanced Threat Protection")
        self.geometry("1100x700")
        self.configure(fg_color=COLORS["bg_primary"])
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Initialize Logic
        self.scanner = MalwareScanner()
        self.scan_thread = None
        self.current_threat_path = None
        self.current_threat_type = "Generic"
        
        # Statistics tracking
        self.total_threats_found = 0
        self.last_scan_time = "Never"
        
        # Real-time Protection
        self.protector = RealTimeProtector(self.on_realtime_threat_detected, self.scanner)

        # --- Professional Sidebar ---
        self._create_sidebar()
        
        # --- Main Content Area ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=COLORS["bg_primary"])
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        # Create Pages
        self.frames = {}
        for page in ["dashboard", "scan", "quarantine", "settings", "realtime", "quick"]:
            self.frames[page] = ctk.CTkFrame(self.main_frame, fg_color="transparent")
            self.frames[page].grid(row=0, column=0, sticky="nsew")
            self.frames[page].grid_columnconfigure(0, weight=1)
        
        # Setup Pages
        self.setup_dashboard()
        self.setup_scan()
        self.setup_quarantine()
        self.setup_settings()
        self.setup_realtime()
        self.setup_quick_scan()

        # Start on Dashboard
        self.show_frame("dashboard")

    def _create_sidebar(self):
        """Create professional sidebar with branding and navigation"""
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=COLORS["bg_secondary"])
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_propagate(False)

        # Brand Header
        brand_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        brand_frame.grid(row=0, column=0, padx=20, pady=(30, 10), sticky="ew")
        
        self.logo_label = ctk.CTkLabel(
            brand_frame, 
            text="⚡ SENTINEL AI", 
            font=ctk.CTkFont(size=22, weight="bold", family="Roboto"),
            text_color=COLORS["accent"]
        )
        self.logo_label.pack()
        
        self.version_label = ctk.CTkLabel(
            brand_frame, 
            text="v1.0 Pro", 
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_secondary"]
        )
        self.version_label.pack()

        # Separator
        separator = ctk.CTkFrame(self.sidebar_frame, height=2, fg_color=COLORS["border"])
        separator.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        # Navigation Buttons (styled as tabs)
        nav_buttons = [
            ("🏠 Dashboard", "dashboard", 2),
            ("🔍 Scan File", "scan", 3),
            ("🔒 Quarantine", "quarantine", 4),
            ("🛡️Realtime", "realtime", 5),
            ("⚡ Quick Scan", "quick", 6),
            ("⚙️ Settings", "settings", 7)
        ]

        for text, page, row in nav_buttons:
            btn = ctk.CTkButton(
                self.sidebar_frame,
                text=text,
                command=lambda p=page: self.show_frame(p),
                font=ctk.CTkFont(size=14, weight="bold", family="Roboto"),
                fg_color=COLORS["bg_secondary"],
                hover_color=COLORS["accent"],
                text_color=COLORS["text_primary"],
                corner_radius=8,
                height=45,
                anchor="w",
                border_width=0
            )
            btn.grid(row=row, column=0, padx=15, pady=8, sticky="ew")
            # Ensure column expands to fill width
            self.sidebar_frame.grid_columnconfigure(0, weight=1)

    def show_frame(self, name):
        """Switch between pages"""
        for frame in self.frames.values():
            frame.grid_forget()
        self.frames[name].grid(row=0, column=0, sticky="nsew")

    # --- Page: Dashboard ---
    def setup_dashboard(self):
        frame = self.frames["dashboard"]
        
        # Title
        lbl_title = ctk.CTkLabel(
            frame, 
            text="System Status", 
            font=ctk.CTkFont(size=28, weight="bold", family="Roboto"),
            text_color=COLORS["text_primary"]
        )
        lbl_title.pack(pady=(20, 30))

        # Large Visual Status Indicator
        status_container = ctk.CTkFrame(frame, fg_color=COLORS["bg_secondary"], corner_radius=15)
        status_container.pack(pady=20, padx=40, fill="x")
        
        # Status Circle
        self.status_canvas = ctk.CTkCanvas(
            status_container, 
            width=200, 
            height=200, 
            bg=COLORS["bg_secondary"], 
            highlightthickness=0
        )
        self.status_canvas.pack(pady=20)
        
        # Draw Shield/Circle
        self.status_circle = self.status_canvas.create_oval(
            30, 30, 170, 170, 
            fill=COLORS["success"], 
            outline="", 
            width=0
        )
        
        # Status Text
        self.lbl_status_text = ctk.CTkLabel(
            status_container, 
            text="SYSTEM SECURE", 
            font=ctk.CTkFont(size=20, weight="bold", family="Roboto"),
            text_color=COLORS["success"]
        )
        self.lbl_status_text.pack(pady=(0, 20))
        
        # Quick Stats Cards
        stats_frame = ctk.CTkFrame(frame, fg_color="transparent")
        stats_frame.pack(pady=20, fill="x", padx=40)
        stats_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Real-time Status Card
        self.rt_stat_card = self._create_stat_card(
            stats_frame, 
            "Real-time Protection", 
            "OFF", 
            COLORS["text_secondary"]
        )
        self.rt_stat_card.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        # Last Scan Card
        self.last_scan_card = self._create_stat_card(
            stats_frame, 
            "Last Scan", 
            "Never", 
            COLORS["text_secondary"]
        )
        self.last_scan_card.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        # Threats Found Card
        self.threats_card = self._create_stat_card(
            stats_frame, 
            "Threats Found", 
            "0", 
            COLORS["success"]
        )
        self.threats_card.grid(row=0, column=2, padx=10, pady=10, sticky="ew")

    def _create_stat_card(self, parent, title, value, color):
        """Create a quick stat card"""
        card = ctk.CTkFrame(parent, fg_color=COLORS["bg_secondary"], corner_radius=10)
        
        ctk.CTkLabel(
            card, 
            text=title, 
            font=ctk.CTkFont(size=12, family="Roboto"),
            text_color=COLORS["text_secondary"]
        ).pack(pady=(15, 5))
        
        value_lbl = ctk.CTkLabel(
            card, 
            text=value, 
            font=ctk.CTkFont(size=18, weight="bold", family="Roboto"),
            text_color=color
        )
        value_lbl.pack(pady=(0, 15))
        
        # Store reference to value label for updates
        card.value_label = value_lbl
        return card

    def update_dashboard_stats(self):
        """Update dashboard statistics"""
        # Real-time protection status
        rt_status = "ON" if self.sw_realtime.get() == 1 else "OFF"
        rt_color = COLORS["success"] if rt_status == "ON" else COLORS["text_secondary"]
        self.rt_stat_card.value_label.configure(text=rt_status, text_color=rt_color)
        
        # Last scan time
        self.last_scan_card.value_label.configure(text=self.last_scan_time)
        
        # Threats found
        threat_color = COLORS["danger"] if self.total_threats_found > 0 else COLORS["success"]
        self.threats_card.value_label.configure(
            text=str(self.total_threats_found), 
            text_color=threat_color
        )

    # --- Page: Scan ---
    def setup_scan(self):
        frame = self.frames["scan"]
        
        lbl_title = ctk.CTkLabel(
            frame, 
            text="Deep Scan", 
            font=ctk.CTkFont(size=28, weight="bold", family="Roboto"),
            text_color=COLORS["text_primary"]
        )
        lbl_title.pack(pady=(20, 30))

        # Drop Zone Area
        drop_zone = ctk.CTkFrame(
            frame, 
            corner_radius=15, 
            border_width=3, 
            border_color=COLORS["border"],
            fg_color="transparent",
            height=120
        )
        drop_zone.pack(pady=30, padx=60, fill="x")
        
        # Browse Button inside drop zone
        self.btn_browse = ctk.CTkButton(
            drop_zone,
            text="📁 Click to Browse File\n(.exe, .dll, or any file)",
            height=100,
            font=ctk.CTkFont(size=16, family="Roboto"),
            fg_color=COLORS["bg_secondary"],
            hover_color=COLORS["accent"],
            corner_radius=10,
            command=self.browse_file
        )
        self.btn_browse.pack(pady=10, padx=10, fill="both", expand=True)

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(frame, width=500, height=8, corner_radius=4)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=20)
        self.progress_bar.pack_forget()

        # Threat Intelligence Card
        self.result_card = ctk.CTkFrame(
            frame, 
            corner_radius=15, 
            border_width=2, 
            border_color=COLORS["border"],
            fg_color=COLORS["bg_secondary"]
        )
        self.result_card.pack(pady=20, fill="both", padx=60, expand=True)
        self.result_card.pack_forget()

        # Result Card Header
        self.lbl_res_title = ctk.CTkLabel(
            self.result_card, 
            text="Scan Result", 
            font=ctk.CTkFont(size=22, weight="bold", family="Roboto"),
            text_color=COLORS["text_primary"]
        )
        self.lbl_res_title.pack(pady=(20, 10))
        
        # File Name (Bold)
        self.lbl_res_file = ctk.CTkLabel(
            self.result_card, 
            text="File: ...",
            font=ctk.CTkFont(size=14, weight="bold", family="Roboto")
        )
        self.lbl_res_file.pack(pady=5)
        
        # Detection Type Badge
        self.lbl_res_type = ctk.CTkLabel(
            self.result_card, 
            text="Type: ...", 
            font=ctk.CTkFont(size=16, weight="bold", family="Roboto"),
            text_color=COLORS["warning"]
        )
        self.lbl_res_type.pack(pady=8)
        
        # Confidence Label
        conf_label_frame = ctk.CTkFrame(self.result_card, fg_color="transparent")
        conf_label_frame.pack(pady=5)
        
        self.lbl_res_conf_text = ctk.CTkLabel(
            conf_label_frame,
            text="Confidence:",
            font=ctk.CTkFont(size=13, family="Roboto")
        )
        self.lbl_res_conf_text.pack(side="left", padx=5)
        
        self.lbl_res_conf_value = ctk.CTkLabel(
            conf_label_frame,
            text="0%",
            font=ctk.CTkFont(size=13, weight="bold", family="Roboto")
        )
        self.lbl_res_conf_value.pack(side="left")
        
        # Confidence Bar (Visual Progress)
        self.confidence_bar = ctk.CTkProgressBar(
            self.result_card, 
            width=400, 
            height=20,
            corner_radius=10
        )
        self.confidence_bar.set(0)
        self.confidence_bar.pack(pady=10)
        
        # Protocol Action
        self.lbl_res_protocol = ctk.CTkLabel(
            self.result_card, 
            text="Protocol: Analyzing...",
            font=ctk.CTkFont(size=13, family="Roboto"),
            text_color=COLORS["text_secondary"]
        )
        self.lbl_res_protocol.pack(pady=8)
        
        self.lbl_res_action = ctk.CTkLabel(
            self.result_card, 
            text="Suggested Action: ...",
            font=ctk.CTkFont(size=13, family="Roboto")
        )
        self.lbl_res_action.pack(pady=10)
        
        # Quarantine Button (HIGH-CONTRAST RED)
        self.btn_action_quarantine = ctk.CTkButton(
            self.result_card, 
            text="🔒 MOVE TO QUARANTINE", 
            fg_color=COLORS["danger"], 
            hover_color="#cc0000",
            font=ctk.CTkFont(size=16, weight="bold", family="Roboto"),
            height=45,
            corner_radius=10,
            command=self.action_quarantine
        )
        self.btn_action_quarantine.pack(pady=(10, 20), padx=40, fill="x")
        self.btn_action_quarantine.pack_forget()

    # --- Page: Quarantine ---
    def setup_quarantine(self):
        frame = self.frames["quarantine"]
        
        # Header
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(
            header, 
            text="🔒 Quarantine Vault", 
            font=ctk.CTkFont(size=28, weight="bold", family="Roboto"),
            text_color=COLORS["text_primary"]
        ).pack(side="left")
        
        ctk.CTkButton(
            header, 
            text="🔄 Refresh", 
            width=120,
            height=35,
            font=ctk.CTkFont(size=13, family="Roboto"),
            fg_color=COLORS["accent"],
            hover_color="#1fa5d0",
            corner_radius=8,
            command=self.load_quarantine_list
        ).pack(side="right")
        
        ctk.CTkLabel(
            frame, 
            text="Secure Storage for Isolated Threats",
            font=ctk.CTkFont(size=13, family="Roboto"),
            text_color=COLORS["text_secondary"]
        ).pack(pady=(0, 15))

        # Tabbed Interface: Active Threats vs History
        self.quarantine_tabview = ctk.CTkTabview(
            frame,
            fg_color=COLORS["bg_secondary"],
            segmented_button_fg_color=COLORS["bg_primary"],
            segmented_button_selected_color=COLORS["accent"],
            segmented_button_selected_hover_color="#1fa5d0"
        )
        self.quarantine_tabview.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Create tabs
        self.quarantine_tabview.add("Active Threats")
        self.quarantine_tabview.add("History")
        
        # Active Threats List
        self.quarantine_list = ctk.CTkScrollableFrame(
            self.quarantine_tabview.tab("Active Threats"),
            fg_color="transparent"
        )
        self.quarantine_list.pack(fill="both", expand=True, padx=10, pady=10)
        
        # History List
        self.history_list = ctk.CTkScrollableFrame(
            self.quarantine_tabview.tab("History"),
            fg_color="transparent"
        )
        self.history_list.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Load initial data
        self.load_quarantine_list()

    def load_quarantine_list(self):
        """Load both active and history quarantine data"""
        # Sync first
        sync_quarantine_vault()

        # Clear existing widgets
        for widget in self.quarantine_list.winfo_children():
            widget.destroy()
        for widget in self.history_list.winfo_children():
            widget.destroy()

        # Path to log
        log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "quarantine.json")
        
        if not os.path.exists(log_path):
            ctk.CTkLabel(
                self.quarantine_list, 
                text="No quarantined items found.",
                text_color=COLORS["text_secondary"]
            ).pack(pady=20)
            ctk.CTkLabel(
                self.history_list, 
                text="No history available.",
                text_color=COLORS["text_secondary"]
            ).pack(pady=20)
            return

        try:
            with open(log_path, 'r') as f:
                logs = json.load(f)
                
            # Filter: Active threats
            active_logs = [e for e in logs if e.get('status') == "Quarantined"]
            # History: All entries
            history_logs = logs

            # Display Active Threats
            if not active_logs:
                ctk.CTkLabel(
                    self.quarantine_list, 
                    text="✓ Vault is empty (No active threats).",
                    text_color=COLORS["success"],
                    font=ctk.CTkFont(size=14, family="Roboto")
                ).pack(pady=30)
            else:
                for entry in reversed(active_logs):
                    self.create_quarantine_item(entry, self.quarantine_list, show_actions=True)
            
            # Display History
            if not history_logs:
                ctk.CTkLabel(
                    self.history_list, 
                    text="No history available.",
                    text_color=COLORS["text_secondary"]
                ).pack(pady=30)
            else:
                for entry in reversed(history_logs):
                    self.create_quarantine_item(entry, self.history_list, show_actions=False)
                
        except Exception as e:
            ctk.CTkLabel(
                self.quarantine_list, 
                text=f"Error loading vault: {e}",
                text_color=COLORS["danger"]
            ).pack(pady=20)

    def create_quarantine_item(self, entry, parent, show_actions=True):
        """Create a quarantine item card"""
        item = ctk.CTkFrame(
            parent, 
            fg_color=COLORS["bg_secondary"], 
            corner_radius=10,
            border_width=1,
            border_color=COLORS["border"]
        )
        item.pack(fill="x", pady=5, padx=5)
        
        # Left: Icon
        type_lbl = ctk.CTkLabel(
            item, 
            text="☣️", 
            font=ctk.CTkFont(size=28)
        )
        type_lbl.pack(side="left", padx=20, pady=15)
        
        # Middle: Details
        details = ctk.CTkFrame(item, fg_color="transparent")
        details.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        orig_path = entry.get("original_path", "Unknown")
        fname = os.path.basename(orig_path)
        timestamp = entry.get("timestamp", "").replace("T", " ")[:19]
        threat = entry.get("threat_type", "Unknown Threat")
        status = entry.get("status", "Quarantined")
        
        # File name
        ctk.CTkLabel(
            details, 
            text=fname, 
            font=ctk.CTkFont(size=15, weight="bold", family="Roboto"), 
            anchor="w",
            text_color=COLORS["text_primary"]
        ).pack(fill="x")
        
        # Threat type and timestamp
        info_text = f"{threat} • {timestamp}"
        ctk.CTkLabel(
            details, 
            text=info_text, 
            font=ctk.CTkFont(size=12, family="Roboto"), 
            text_color=COLORS["text_secondary"], 
            anchor="w"
        ).pack(fill="x")
        
        # Status badge (for history tab)
        if not show_actions or status != "Quarantined":
            status_colors = {
                "Quarantined": COLORS["danger"],
                "Restored": COLORS["success"],
                "Deleted": COLORS["text_secondary"]
            }
            status_badge = ctk.CTkLabel(
                details,
                text=f"Status: {status.upper()}",
                font=ctk.CTkFont(size=11, weight="bold", family="Roboto"),
                text_color=status_colors.get(status, COLORS["text_secondary"])
            )
            status_badge.pack(fill="x", pady=(3, 0))
        
        # Right: Action Buttons (only for active threats)
        if show_actions and status == "Quarantined":
            actions_frame = ctk.CTkFrame(item, fg_color="transparent")
            actions_frame.pack(side="right", padx=15, pady=10)
            
            ctk.CTkButton(
                actions_frame, 
                text="🔓 Restore", 
                fg_color=COLORS["success"], 
                hover_color="#00cc7a",
                width=90,
                height=32,
                corner_radius=8,
                font=ctk.CTkFont(size=12, family="Roboto"),
                command=lambda e=entry: self.on_restore(e)
            ).pack(side="left", padx=5)
            
            ctk.CTkButton(
                actions_frame, 
                text="🗑️ Delete", 
                fg_color=COLORS["danger"], 
                hover_color="#cc0000",
                width=90,
                height=32,
                corner_radius=8,
                font=ctk.CTkFont(size=12, family="Roboto"),
                command=lambda e=entry: self.on_delete(e)
            ).pack(side="left", padx=5)

    def on_restore(self, entry):
        """Restore a quarantined file"""
        path = entry.get("original_path")
        if path:
            msg = restore_file(path)
            print(msg)
            self.after(200, self.load_quarantine_list)
            
            if self.current_threat_path and path and os.path.normpath(path) == os.path.normpath(self.current_threat_path):
                self.clear_scan_result()

    def on_delete(self, entry):
        """Permanently delete a quarantined file"""
        path = entry.get("original_path")
        if path:
            msg = delete_quarantined_file(path)
            print(msg)
            self.after(200, self.load_quarantine_list)
            
            if self.current_threat_path and path and os.path.normpath(path) == os.path.normpath(self.current_threat_path):
                self.clear_scan_result()

    def clear_scan_result(self):
        """Reset scan page UI"""
        self.result_card.pack_forget()
        self.current_threat_path = None
        self.btn_browse.configure(state="normal")
        self.lbl_status_text.configure(text="SYSTEM SECURE", text_color=COLORS["success"])
        self.status_canvas.itemconfig(self.status_circle, fill=COLORS["success"])

    # --- Page: Settings ---
    def setup_settings(self):
        frame = self.frames["settings"]
        
        ctk.CTkLabel(
            frame, 
            text="⚙️ Settings", 
            font=ctk.CTkFont(size=28, weight="bold", family="Roboto"),
            text_color=COLORS["text_primary"]
        ).pack(pady=(20, 30))
        
        settings_container = ctk.CTkFrame(frame, fg_color=COLORS["bg_secondary"], corner_radius=15)
        settings_container.pack(pady=20, padx=60, fill="both", expand=True)
        
        ctk.CTkLabel(
            settings_container, 
            text="General Settings",
            font=ctk.CTkFont(size=16, weight="bold", family="Roboto")
        ).pack(pady=(20, 15))
        
        self.sw_notify = ctk.CTkSwitch(
            settings_container, 
            text="Enable Notifications",
            font=ctk.CTkFont(size=14, family="Roboto"),
            progress_color=COLORS["accent"]
        )
        self.sw_notify.select()
        self.sw_notify.pack(pady=10, padx=30, anchor="w")
        
        self.sw_auto_q = ctk.CTkSwitch(
            settings_container, 
            text="Auto-Quarantine High Threats",
            font=ctk.CTkFont(size=14, family="Roboto"),
            progress_color=COLORS["accent"]
        )
        self.sw_auto_q.pack(pady=10, padx=30, anchor="w")
        
        # About Section
        ctk.CTkLabel(
            settings_container, 
            text="About",
            font=ctk.CTkFont(size=16, weight="bold", family="Roboto")
        ).pack(pady=(30, 15))
        
        ctk.CTkLabel(
            settings_container,
            text="SENTINEL AI v1.0 Pro\nCybersecurity Protection Suite",
            font=ctk.CTkFont(size=12, family="Roboto"),
            text_color=COLORS["text_secondary"]
        ).pack(pady=10)


    # --- Page: Realtime ---
    def setup_realtime(self):
        frame = self.frames["realtime"]
        
        ctk.CTkLabel(
            frame, 
            text="🛡️ Real-time Protection", 
            font=ctk.CTkFont(size=28, weight="bold", family="Roboto"),
            text_color=COLORS["text_primary"]
        ).pack(pady=(20, 30))
        
        rt_container = ctk.CTkFrame(frame, fg_color=COLORS["bg_secondary"], corner_radius=15)
        rt_container.pack(pady=20, padx=60, fill="both", expand=True)
        
        # Center container for status
        center_frame = ctk.CTkFrame(rt_container, fg_color="transparent")
        center_frame.pack(expand=True, fill="both")
        
        # Status Icon
        self.rt_status_canvas = ctk.CTkCanvas(
            center_frame, 
            width=150, 
            height=150, 
            bg=COLORS["bg_secondary"], 
            highlightthickness=0
        )
        self.rt_status_canvas.pack(pady=(30, 20))
        self.rt_status_circle = self.rt_status_canvas.create_oval(
            15, 15, 135, 135, 
            fill=COLORS["border"], 
            outline=""
        )
        
        self.lbl_rt_status = ctk.CTkLabel(
            center_frame, 
            text="PROTECTION OFF", 
            font=ctk.CTkFont(size=20, weight="bold", family="Roboto"), 
            text_color=COLORS["text_secondary"]
        )
        self.lbl_rt_status.pack(pady=10)
        
        self.sw_realtime = ctk.CTkSwitch(
            center_frame, 
            text="Enable Real-time Protection", 
            command=self.toggle_realtime, 
            font=ctk.CTkFont(size=16, family="Roboto"),
            progress_color=COLORS["success"]
        )
        self.sw_realtime.pack(pady=20)
        
        ctk.CTkLabel(
            center_frame, 
            text="📂 Monitored Folder: Downloads", 
            text_color=COLORS["text_secondary"],
            font=ctk.CTkFont(size=13, family="Roboto")
        ).pack(pady=(5, 20))

    # --- Page: Quick Scan ---
    def setup_quick_scan(self):
        frame = self.frames["quick"]
        
        ctk.CTkLabel(
            frame, 
            text="⚡ Custom Scan", 
            font=ctk.CTkFont(size=28, weight="bold", family="Roboto"),
            text_color=COLORS["text_primary"]
        ).pack(pady=(20, 10))
        
        ctk.CTkLabel(
            frame, 
            text="Select a folder to scan recursively for threats.", 
            text_color=COLORS["text_secondary"],
            font=ctk.CTkFont(size=13, family="Roboto")
        ).pack(pady=(0, 20))
        
        # Folder Selection
        self.selected_folder_path = None
        
        select_frame = ctk.CTkFrame(frame, fg_color=COLORS["bg_secondary"], corner_radius=10)
        select_frame.pack(pady=10, padx=60, fill="x")
        
        self.btn_select_folder = ctk.CTkButton(
            select_frame, 
            text="📁 Select Folder", 
            height=40, 
            font=ctk.CTkFont(size=14, weight="bold", family="Roboto"),
            fg_color=COLORS["accent"],
            hover_color="#1fa5d0",
            corner_radius=8,
            command=self.select_scan_folder
        )
        self.btn_select_folder.pack(pady=15, padx=20)
        
        self.lbl_selected_folder = ctk.CTkLabel(
            select_frame, 
            text="No folder selected", 
            text_color=COLORS["text_secondary"],
            font=ctk.CTkFont(size=12, family="Roboto")
        )
        self.lbl_selected_folder.pack(pady=(0, 15))

        self.btn_start_quick = ctk.CTkButton(
            frame, 
            text="▶️ Start Scan", 
            height=50, 
            width=200, 
            font=ctk.CTkFont(size=16, weight="bold", family="Roboto"),
            fg_color=COLORS["success"],
            hover_color="#00cc7a",
            corner_radius=10,
            command=self.start_quick_scan
        )
        self.btn_start_quick.pack(pady=20)
        
        self.quick_progress = ctk.CTkProgressBar(frame, width=400)
        self.quick_progress.set(0)
        self.quick_progress.pack(pady=20)
        self.quick_progress.pack_forget()
        
        self.lbl_quick_status = ctk.CTkLabel(
            frame, 
            text="Ready to scan.",
            font=ctk.CTkFont(size=13, family="Roboto")
        )
        self.lbl_quick_status.pack(pady=10)
        
        # Results List
        self.quick_results_frame = ctk.CTkScrollableFrame(
            frame, 
            width=700, 
            height=300,
            fg_color=COLORS["bg_secondary"],
            corner_radius=10
        )
        self.quick_results_frame.pack(pady=10, padx=60, fill="both", expand=True)

    def select_scan_folder(self):
        """Select folder for quick scan"""
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.selected_folder_path = folder_selected
            self.lbl_selected_folder.configure(
                text=f"Selected: {self.selected_folder_path}", 
                text_color=COLORS["text_primary"]
            )
            self.lbl_quick_status.configure(text="Ready to scan.")

    def start_quick_scan(self):
        """Start quick scan process"""
        if not self.selected_folder_path:
            self.lbl_quick_status.configure(
                text="⚠️ Please select a folder first!", 
                text_color=COLORS["warning"]
            )
            return

        self.btn_start_quick.configure(state="disabled")
        self.btn_select_folder.configure(state="disabled")
        
        self.quick_progress.pack(pady=20)
        self.quick_progress.start()
        self.lbl_quick_status.configure(
            text=f"Scanning {os.path.basename(self.selected_folder_path)}...", 
            text_color=COLORS["text_primary"]
        )
        
        # Clear previous results
        for widget in self.quick_results_frame.winfo_children():
            widget.destroy()
            
        threading.Thread(target=self.run_quick_scan_logic).start()

    def run_quick_scan_logic(self):
        """Execute quick scan in background thread"""
        target = self.selected_folder_path
        threats = []
        
        try:
            for result in self.scanner.scan_directory(target):
                threats.append(result)
        except Exception as e:
            print(f"Error checking directory: {e}")
        
        self.after(0, lambda: self.finish_quick_scan(threats))

    def finish_quick_scan(self, threats):
        """Display quick scan results"""
        self.quick_progress.stop()
        self.quick_progress.pack_forget()
        self.btn_start_quick.configure(state="normal")
        self.btn_select_folder.configure(state="normal")
        
        if not threats:
            self.lbl_quick_status.configure(
                text="✓ Scan Complete. No threats found!",
                text_color=COLORS["success"]
            )
            ctk.CTkLabel(
                self.quick_results_frame, 
                text="✓ No threats found. System is clean.", 
                text_color=COLORS["success"],
                font=ctk.CTkFont(size=14, family="Roboto")
            ).pack(pady=30)
        else:
            self.lbl_quick_status.configure(
                text=f"⚠️ Scan Complete. {len(threats)} threats found!",
                text_color=COLORS["danger"]
            )
            for threat in threats:
                self.add_quick_result_item(threat)

    def add_quick_result_item(self, threat):
        """Add a threat item to quick scan results"""
        item = ctk.CTkFrame(
            self.quick_results_frame,
            fg_color=COLORS["bg_primary"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["danger"]
        )
        item.pack(fill="x", pady=5, padx=5)
        
        ctk.CTkLabel(
            item, 
            text=f"⚠️ {os.path.basename(threat['file_path'])}", 
            text_color=COLORS["danger"], 
            anchor="w",
            font=ctk.CTkFont(size=13, weight="bold", family="Roboto")
        ).pack(side="left", padx=15, pady=10)
        
        ctk.CTkLabel(
            item, 
            text=threat.get('Type', 'Unknown'), 
            anchor="w",
            font=ctk.CTkFont(size=12, family="Roboto"),
            text_color=COLORS["text_secondary"]
        ).pack(side="left", padx=10)
        
        ctk.CTkButton(
            item, 
            text="🔒 Quarantine", 
            width=100, 
            fg_color=COLORS["danger"],
            hover_color="#cc0000",
            corner_radius=6,
            font=ctk.CTkFont(size=11, family="Roboto"),
            command=lambda p=threat['file_path'], t=threat.get('Type', 'Generic'): self.quick_quarantine(p, t, item)
        ).pack(side="right", padx=10, pady=5)

    def quick_quarantine(self, path, threat_type, widget):
        """Quarantine a threat from quick scan results"""
        res = quarantine_file(path, threat_type)
        print(res)
        widget.destroy()

    # --- Scanning Logic ---
    def browse_file(self):
        """Open file browser for scan"""
        file_path = filedialog.askopenfilename(
            filetypes=[
                ("Executables", "*.exe"), 
                ("DLLs", "*.dll"), 
                ("All Files", "*.*")
            ]
        )
        if file_path:
            self.start_scan(file_path)

    def start_scan(self, file_path):
        """Start file scan process"""
        # Reset UI
        self.result_card.pack_forget()
        self.progress_bar.pack(pady=20)
        self.progress_bar.set(0)
        self.btn_browse.configure(state="disabled")
        
        # Start Thread
        self.scan_thread = threading.Thread(target=self.run_scan_logic, args=(file_path,))
        self.scan_thread.start()
        
        # Animate progress bar
        self.animate_progress()

    def animate_progress(self):
        """Animate progress bar during scan"""
        if self.scan_thread and self.scan_thread.is_alive():
            current = self.progress_bar.get()
            if current < 0.9:
                self.progress_bar.set(current + 0.05)
            self.after(100, self.animate_progress)
        else:
            self.progress_bar.set(1.0)
            self.btn_browse.configure(state="normal")

    def run_scan_logic(self, file_path):
        """Execute scan in background thread"""
        time.sleep(1.0)  # UX delay
        result = self.scanner.scan_file(file_path)
        
        # Schedule UI update
        self.after(0, lambda: self.display_result(result))

    def display_result(self, result):
        """Display scan results in threat intelligence card"""
        # Update last scan time
        self.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M")
        
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
            
            # Update threat counter
            if is_malware or is_suspicious:
                self.total_threats_found += 1
        else:
            is_malware = False
            is_suspicious = False
            confidence = 0
            fname = "N/A"
            protocol = str(result)
            self.current_threat_path = None

        # Update dashboard stats
        self.update_dashboard_stats()

        # Show result card
        self.result_card.pack(pady=20, fill="both", padx=60, expand=True)
        
        if is_malware:
            # MALWARE DETECTED
            self.result_card.configure(border_color=COLORS["danger"])
            self.lbl_res_title.configure(
                text="⚠️ THREAT DETECTED", 
                text_color=COLORS["danger"]
            )
            self.lbl_res_file.configure(text=f"File: {fname}")
            self.lbl_res_conf_value.configure(
                text=f"{confidence:.2f}%",
                text_color=COLORS["danger"]
            )
            
            # Confidence bar
            self.confidence_bar.set(confidence / 100)
            
            # Detection type
            self.lbl_res_type.configure(
                text=f"🔴 Detected: {threat_type.upper()}",
                text_color=COLORS["danger"]
            )
            self.lbl_res_type.pack(pady=8)
            
            # Protocol
            self.lbl_res_protocol.configure(text=f"Protocol: {protocol}")
            self.lbl_res_protocol.pack(pady=8)

            self.lbl_res_action.configure(
                text="⚠️ Action: Immediate Quarantine Recommended", 
                text_color=COLORS["warning"]
            )
            
            # Show Quarantine Button
            self.btn_action_quarantine.pack(pady=(10, 20), padx=40, fill="x")
            
            # Dashboard Indicator Red
            self.status_canvas.itemconfig(self.status_circle, fill=COLORS["danger"])
            self.lbl_status_text.configure(text="THREAT FOUND", text_color=COLORS["danger"])
            
        elif is_suspicious:
            # SUSPICIOUS FILE
            self.result_card.configure(border_color=COLORS["warning"])
            self.lbl_res_title.configure(
                text="⚠️ SUSPICIOUS FILE", 
                text_color=COLORS["warning"]
            )
            self.lbl_res_file.configure(text=f"File: {fname}")
            self.lbl_res_conf_value.configure(
                text=f"{confidence:.2f}% (Medium)",
                text_color=COLORS["warning"]
            )
            
            # Confidence bar
            self.confidence_bar.set(confidence / 100)
            
            # Detection type
            self.lbl_res_type.configure(
                text="🟡 Status: Requires Manual Review",
                text_color=COLORS["warning"]
            )
            self.lbl_res_type.pack(pady=8)
            
            # Protocol
            self.lbl_res_protocol.configure(
                text="Recommendation: Manual inspection advised"
            )
            self.lbl_res_protocol.pack(pady=8)

            self.lbl_res_action.configure(
                text="Action: Review file manually or quarantine if unsure", 
                text_color=COLORS["warning"]
            )
            
            # Show Quarantine Button
            self.btn_action_quarantine.pack(pady=(10, 20), padx=40, fill="x")
            
            # Dashboard Indicator Yellow
            self.status_canvas.itemconfig(self.status_circle, fill=COLORS["warning"])
            self.lbl_status_text.configure(text="SUSPICIOUS FILE", text_color=COLORS["warning"])
            
        else:
            # CLEAN FILE
            self.result_card.configure(border_color=COLORS["success"])
            self.lbl_res_title.configure(
                text="✓ Clean File", 
                text_color=COLORS["success"]
            )
            self.lbl_res_file.configure(text=f"File: {fname}")
            self.lbl_res_conf_value.configure(
                text=f"{confidence:.2f}% (Benign)",
                text_color=COLORS["success"]
            )
            
            # Confidence bar
            self.confidence_bar.set(confidence / 100)
            
            # Hide threat details
            self.lbl_res_type.pack_forget()
            self.lbl_res_protocol.pack_forget()
            
            self.lbl_res_action.configure(
                text="✓ System is safe. No action required.", 
                text_color=COLORS["success"]
            )
            
            # Hide Quarantine Button
            self.btn_action_quarantine.pack_forget()

            # Dashboard Indicator Green
            self.status_canvas.itemconfig(self.status_circle, fill=COLORS["success"])
            self.lbl_status_text.configure(text="SYSTEM SECURE", text_color=COLORS["success"])

    def action_quarantine(self):
        """Quarantine the currently scanned threat"""
        if self.current_threat_path:
            res = quarantine_file(self.current_threat_path, self.current_threat_type)
            
            # Update UI to show success
            self.lbl_res_action.configure(
                text=f"✓ {res}", 
                text_color=COLORS["success"]
            )
            self.btn_action_quarantine.pack_forget()
            
            # Update status
            self.status_canvas.itemconfig(self.status_circle, fill=COLORS["warning"])
            self.lbl_status_text.configure(
                text="THREAT QUARANTINED", 
                text_color=COLORS["warning"]
            )
            
            # Hide the card
            self.result_card.pack_forget()
            self.current_threat_path = None

    def toggle_realtime(self):
        """Toggle real-time protection on/off"""
        if self.sw_realtime.get() == 1:
            self.protector.start()
            self.lbl_rt_status.configure(
                text="PROTECTING", 
                text_color=COLORS["success"]
            )
            self.rt_status_canvas.itemconfig(
                self.rt_status_circle, 
                fill=COLORS["success"]
            )
        else:
            self.protector.stop()
            self.lbl_rt_status.configure(
                text="PROTECTION OFF", 
                text_color=COLORS["text_secondary"]
            )
            self.rt_status_canvas.itemconfig(
                self.rt_status_circle, 
                fill=COLORS["border"]
            )
        
        # Update dashboard
        self.update_dashboard_stats()

    def on_realtime_threat_detected(self, result):
        """Callback from real-time protection"""
        self.after(0, lambda: self._handle_realtime_alert(result))

    def _handle_realtime_alert(self, result):
        """Handle real-time threat alert"""
        # Switch to dashboard
        self.show_frame("dashboard")
        
        fname = result.get("file_name", "Unknown")
        threat_type = result.get("Type", "Unknown")
        
        self.status_canvas.itemconfig(self.status_circle, fill=COLORS["danger"])
        self.lbl_status_text.configure(
            text=f"REAL-TIME THREAT: {fname}", 
            text_color=COLORS["danger"]
        )
        
        # Show details in scan page
        self.display_result(result)
        self.show_frame("scan")

if __name__ == "__main__":
    app = AntivirusApp()
    app.mainloop()
