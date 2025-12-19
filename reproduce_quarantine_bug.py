import os
import sys
import json
import shutil

# Ensure we can import src
sys.path.insert(0, os.path.abspath("src"))

from quarantine import quarantine_file, sync_quarantine_vault, QUARANTINE_LOG_FILE, QUARANTINE_DIR

def run_test():
    print("--- Reproduction Test ---")
    
    # 1. Setup Dummy File
    test_file = os.path.abspath("test_q_bug.txt")
    with open(test_file, 'w') as f:
        f.write("Malware data")
    
    print(f"Created {test_file}")
    
    # 2. Quarantine it
    msg = quarantine_file(test_file, "Test Threat")
    print(msg)
    
    # 3. Check Log explicitly
    with open(QUARANTINE_LOG_FILE, 'r') as f:
        data = json.load(f)
    print(f"Log after quarantine (Status): {data[-1]['status']}")
    print(f"Log after quarantine (Path): {data[-1]['original_path']}")
    
    # 4. Check Vault file exists
    fname = os.path.basename(test_file)
    locked_name = fname + ".LOCKED"
    vault_path = os.path.join(QUARANTINE_DIR, locked_name)
    print(f"Vault file exists: {os.path.exists(vault_path)}")
    
    # 5. Run Sync (The suspected culprit)
    print("Running sync_quarantine_vault()...")
    sync_quarantine_vault()
    
    # 6. Check Log again
    with open(QUARANTINE_LOG_FILE, 'r') as f:
        data = json.load(f)
    print(f"Log after sync (Status): {data[-1]['status']}")
    
    if data[-1]['status'] != 'Quarantined':
        print("[FAIL] Status changed incorrectly!")
    else:
        print("[PASS] Status persisted.")

    # Cleanup
    # if os.path.exists(vault_path): os.remove(vault_path)

if __name__ == "__main__":
    run_test()
