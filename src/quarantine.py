
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

if __name__ == "__main__":
    # Test
    test_file = "test_virus.txt"
    with open(test_file, 'w') as f:
        f.write("I am a test virus")
    
    print(f"Created {test_file}")
    result = quarantine_file(test_file, "Test Threat")
    print(result)
