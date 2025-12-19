
import os
import shutil
import json
import datetime

# --- Configuration ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUARANTINE_DIR = os.path.join(PROJECT_ROOT, "quarantine_vault")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
QUARANTINE_LOG_FILE = os.path.join(LOGS_DIR, "quarantine.json")

def setup_directories():
    """Ensure quarantine and log directories exist."""
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)
    if not os.path.exists(QUARANTINE_LOG_FILE):
        with open(QUARANTINE_LOG_FILE, 'w') as f:
            json.dump([], f)

def log_quarantine(original_path, threat_type):
    """Log the quarantine action."""
    entry = {
        "original_path": original_path,
        "timestamp": datetime.datetime.now().isoformat(),
        "threat_type": threat_type,
        "status": "Quarantined"
    }
    
    try:
        with open(QUARANTINE_LOG_FILE, 'r') as f:
            logs = json.load(f)
    except:
        logs = []
        
    logs.append(entry)
    
    with open(QUARANTINE_LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

def get_quarantined_files():
    """Returns the list of quarantined files from the log."""
    setup_directories()
    try:
        with open(QUARANTINE_LOG_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def quarantine_file(file_path, threat_type="Generic Malware"):
    """
    Moves a file to quarantine.
    1. Copies file to quarantine_store
    2. Renames extension to .VIRUS_LOCKED
    3. Deletes original
    4. Logs action
    """
    setup_directories()
    
    if not os.path.exists(file_path):
        return f"Error: File {file_path} not found."

    try:
        file_name = os.path.basename(file_path)
        new_name = file_name + ".LOCKED"
        destination = os.path.join(QUARANTINE_DIR, new_name)

        # 1. Copy (Move logic safer with copy then delete)
        shutil.copy2(file_path, destination)
        
        # 2. Delete Original
        os.remove(file_path)
        
        # 3. Log
        log_quarantine(file_path, threat_type)
        
        return f"SUCCESS: File quarantined to {new_name}"
        
    except Exception as e:
        return f"Error during quarantine: {e}"

    
def sync_quarantine_vault():
    """
    Syncs the log file with the actual files in the vault.
    1. If file exists in vault but not log -> Add it (Unknown Threat).
    2. If file in log (Quarantined) but not in vault -> Mark Deleted.
    """
    setup_directories()
    
    try:
        with open(QUARANTINE_LOG_FILE, 'r') as f:
            logs = json.load(f)
    except:
        logs = []
        
    # Map logs by locked filename (derived from original path)
    # Use lowercase keys for case-insensitive matching on Windows
    log_map = {}
    for entry in logs:
        # Reconstruct locked name: basename + .LOCKED
        locked_name = os.path.basename(entry['original_path']) + ".LOCKED"
        log_map[locked_name.lower()] = entry

    # 1. Scan Vault for unlogged files
    vault_files = os.listdir(QUARANTINE_DIR)
    vault_files_lower = {f.lower(): f for f in vault_files}  # Case-insensitive lookup
    
    for fname in vault_files:
        if not fname.endswith(".LOCKED"):
            continue
            
        if fname.lower() not in log_map:
            # Found orphan file, add to log
            original_name = fname.replace(".LOCKED", "")
            # We don't know the full original path, so we guess/placeholder
            # In a real app, we might store metadata in the file itself.
            entry = {
                "original_path": os.path.join("RestoredFromVault", original_name),
                "timestamp": datetime.datetime.now().isoformat(),
                "threat_type": "Unknown (Orphan)",
                "status": "Quarantined"
            }
            logs.append(entry)
            
        else:
            # File exists and is in log. Ensure status is Quarantined if it was marked otherwise?
            # User might have manually put it back? 
            # For now, trust the log unless it says 'Deleted' but file is there.
            entry = log_map[fname.lower()]
            if entry['status'] in ['Deleted', 'Restored']:
                # Weird state: Log says gone, but file is here. Resurrect it.
                entry['status'] = "Quarantined"

    # 2. Check for missing files (case-insensitive)
    for entry in logs:
        if entry['status'] == "Quarantined":
            locked_name = os.path.basename(entry['original_path']) + ".LOCKED"
            if locked_name.lower() not in vault_files_lower:
                entry['status'] = "Missing"

    # Save
    with open(QUARANTINE_LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

def update_log_status(original_path, new_status):
    """Helper to update the status of a log entry."""
    try:
        with open(QUARANTINE_LOG_FILE, 'r') as f:
            logs = json.load(f)
    except:
        return

    for entry in logs:
        if entry['original_path'] == original_path:
            # Update the most recent 'Quarantined' entry or just the last match
            entry['status'] = new_status
            
    with open(QUARANTINE_LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

def restore_file(original_path):
    """
    Restores a file from quarantine to its original location.
    """
    setup_directories()
    
    file_name = os.path.basename(original_path)
    locked_name = file_name + ".LOCKED"
    source = os.path.join(QUARANTINE_DIR, locked_name)
    
    if not os.path.exists(source):
        return f"Error: Quarantined file {locked_name} not found."
        
    try:
        # Move back
        shutil.move(source, original_path)
        update_log_status(original_path, "Restored")
        return f"SUCCESS: File restored to {original_path}"
    except Exception as e:
        return f"Error restoring file: {e}"

def delete_quarantined_file(original_path):
    """
    Permanently deletes the file from quarantine.
    """
    setup_directories()
    
    file_name = os.path.basename(original_path)
    locked_name = file_name + ".LOCKED"
    source = os.path.join(QUARANTINE_DIR, locked_name)
    
    if not os.path.exists(source):
        return f"Error: File {locked_name} already gone."
        
    try:
        os.remove(source)
        update_log_status(original_path, "Deleted")
        return f"SUCCESS: File permanently deleted."
    except Exception as e:
        return f"Error deleting file: {e}"

if __name__ == "__main__":
    # Test
    test_file = "test_virus.txt"
    with open(test_file, 'w') as f:
        f.write("I am a test virus")
    
    print(f"Created {test_file}")
    res = quarantine_file(test_file, "Test Threat")
    print(res)
    
    # input("Press enter to restore...")
    # print(restore_file(os.path.abspath(test_file)))

