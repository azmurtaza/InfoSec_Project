
import json
import os
import datetime

# Mock UI interactions
def load_quarantine_list():
    log_path = os.path.join("logs", "quarantine.json")
    print(f"Reading from {log_path}")
    
    if not os.path.exists(log_path):
        print("Log not found.")
        return

    with open(log_path, 'r') as f:
        logs = json.load(f)
        
    print(f"Found {len(logs)} entries.")
    for entry in reversed(logs):
        print(f" - {entry.get('threat_type')} | {entry.get('original_path')}")

if __name__ == "__main__":
    # Ensure dir
    if not os.path.exists("logs"):
        os.makedirs("logs")
        
    # Write dummy data
    dummy_data = [
        {
            "original_path": "C:/Downloads/virus.exe",
            "timestamp": datetime.datetime.now().isoformat(),
            "threat_type": "Ransomware",
            "status": "Quarantined"
        }
    ]
    with open("logs/quarantine.json", 'w') as f:
        json.dump(dummy_data, f)
        
    print("Created mock log.")
    load_quarantine_list()
