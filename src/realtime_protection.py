import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scanner_engine import MalwareScanner

class RealTimeHandler(FileSystemEventHandler):
    def __init__(self, callback, scanner=None):
        if scanner:
            self.scanner = scanner
        else:
            self.scanner = MalwareScanner()
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self.scan(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.scan(event.src_path)

    def scan(self, file_path):
        # Small delay to ensure file write is complete
        time.sleep(1.0)
        
        # Filter for executable-like content to avoid scanning every temp file
        # IMPORTANT: This explicitly includes .dll, .exe, .sys, and script files
        valid_extensions = ('.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.ps1', '.vbs', '.msi')
        if not file_path.lower().endswith(valid_extensions):
             # Skip non-executable files to reduce false positives and improve performance
             return

        print(f"[RealTime] Scanning modified/created file: {file_path}")
        try:
            result = self.scanner.scan_file(file_path)
            
            # Check if it is malware
            if isinstance(result, dict) and result.get("status") == "malware":
                print(f"[RealTime] THREAT DETECTED in {file_path}!")
                # Trigger callback to UI
                if self.callback:
                    self.callback(result)
        except Exception as e:
            print(f"[RealTime] Error scanning {file_path}: {e}")

class RealTimeProtector:
    def __init__(self, threat_callback, scanner=None, initial_path=None):
        self.observer = Observer()
        self.handler = RealTimeHandler(threat_callback, scanner)
        # Default to Downloads, but allow custom initial path
        if initial_path and os.path.exists(initial_path):
            self.watch_path = initial_path
        else:
            self.watch_path = os.path.join(os.path.expanduser("~"), "Downloads")
        self.is_running = False

    def start(self):
        if not self.is_running:
            if not os.path.exists(self.watch_path):
                print(f"[RealTime] Watch path does not exist: {self.watch_path}")
                return False

            self.observer = Observer() # Re-create observer on restart
            # IMPORTANT: recursive=True enables monitoring of all subfolders
            self.observer.schedule(self.handler, self.watch_path, recursive=True)
            self.observer.start()
            self.is_running = True
            print(f"[RealTime] Protection Started. Watching: {self.watch_path} (recursive)")
            return True

    def stop(self):
        if self.is_running:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            print("[RealTime] Protection Stopped.")
    
    def set_watch_path(self, path):
        """Change the monitored folder path. Restarts protection if currently running."""
        if not os.path.exists(path):
            print(f"[RealTime] Invalid path: {path}")
            return False
        
        if not os.path.isdir(path):
            print(f"[RealTime] Path is not a directory: {path}")
            return False
        
        # Stop current monitoring if running
        was_running = self.is_running
        if was_running:
            self.stop()
        
        # Update path
        self.watch_path = path
        print(f"[RealTime] Watch path updated to: {self.watch_path}")
        
        # Restart if it was running before
        if was_running:
            return self.start()
        
        return True
    
    def get_watch_path(self):
        """Get the current monitored folder path."""
        return self.watch_path
