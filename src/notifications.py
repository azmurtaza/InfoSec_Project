"""
Windows Desktop Notification System for SENTINEL AI Antivirus
Provides toast notifications for security events
"""

import threading
import os

try:
    from win10toast import ToastNotifier
    NOTIFICATIONS_AVAILABLE = True
except ImportError:
    NOTIFICATIONS_AVAILABLE = False
    print("[!] win10toast not installed. Notifications disabled.")
    print("[*] Install with: pip install win10toast")


class NotificationManager:
    """Manages desktop notifications for security events"""
    
    def __init__(self):
        global NOTIFICATIONS_AVAILABLE
        self.enabled = False
        self.toaster = None
        
        if NOTIFICATIONS_AVAILABLE:
            try:
                self.toaster = ToastNotifier()
            except Exception as e:
                print(f"[!] Failed to initialize toaster: {e}")
                NOTIFICATIONS_AVAILABLE = False
    
    def set_enabled(self, enabled):
        """Enable or disable notifications"""
        self.enabled = enabled
        
        if enabled and NOTIFICATIONS_AVAILABLE:
            # Show test notification when enabled
            self.show_test_notification()
        elif enabled and not NOTIFICATIONS_AVAILABLE:
            print("[!] Notifications enabled but win10toast not available")
    
    def is_enabled(self):
        """Check if notifications are enabled"""
        return self.enabled
    
    def show_test_notification(self):
        """Show test notification when notifications are enabled"""
        if self.enabled and NOTIFICATIONS_AVAILABLE and self.toaster:
            self._notify(
                "🛡️ SENTINEL AI",
                "Notifications enabled successfully"
            )
    
    def notify_malware_detected(self, filename, threat_type="Malware"):
        """Notify when malware is detected"""
        if self.enabled and NOTIFICATIONS_AVAILABLE and self.toaster:
            self._notify(
                "⚠️ Threat Detected!",
                f"{threat_type} found: {filename}"
            )
    
    def notify_quarantined(self, filename):
        """Notify when a file is quarantined"""
        if self.enabled and NOTIFICATIONS_AVAILABLE and self.toaster:
            self._notify(
                "🛡️ File Quarantined",
                f"Isolated: {filename}"
            )
    
    def notify_scan_complete(self, status, filename=None):
        """Notify when scan is complete"""
        if self.enabled and NOTIFICATIONS_AVAILABLE and self.toaster:
            if status == "malware":
                message = f"Threat detected in {filename}" if filename else "Threat detected"
            elif status == "suspicious":
                message = f"Suspicious file: {filename}" if filename else "Suspicious file detected"
            else:
                message = f"{filename} is clean" if filename else "Scan complete - No threats"
            
            self._notify(
                "✓ Scan Complete",
                message
            )
    
    def notify_cloud_escalation(self, filename, engines_flagged):
        """Notify when cloud detection escalates a threat"""
        if self.enabled and NOTIFICATIONS_AVAILABLE and self.toaster:
            self._notify(
                "☁️ Cloud Detection",
                f"{engines_flagged} engines flagged: {filename}"
            )
    
    def notify_realtime_threat(self, filename):
        """Notify when real-time protection detects a threat"""
        if self.enabled and NOTIFICATIONS_AVAILABLE and self.toaster:
            self._notify(
                "🚨 Real-Time Protection",
                f"Blocked threat: {filename}"
            )
    
    def _notify(self, title, message, duration=5):
        """
        Internal method to show notification
        Runs in separate thread to avoid blocking
        """
        if not self.toaster:
            return
        
        def show_toast():
            try:
                self.toaster.show_toast(
                    title,
                    message,
                    duration=duration,
                    icon_path=None,
                    threaded=False
                )
            except Exception as e:
                print(f"[!] Notification error: {e}")
        
        # Run in daemon thread to avoid blocking
        thread = threading.Thread(target=show_toast, daemon=True)
        thread.start()


# Global instance
_notification_manager = None

def get_notification_manager():
    """Get global notification manager instance"""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager
