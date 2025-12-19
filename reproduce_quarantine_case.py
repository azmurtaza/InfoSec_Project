import os
import sys
import json
import shutil

# Ensure we can import src
sys.path.insert(0, os.path.abspath("src"))

from quarantine import quarantine_file, sync_quarantine_vault, QUARANTINE_LOG_FILE, QUARANTINE_DIR

def run_test():
    print("--- Reproduction Test (Case Sensitivity) ---")
    
    # 1. Setup Dummy File (Lowercase on disk)
    filename = "test_case_bug.txt"
    with open(filename, 'w') as f:
        f.write("Malware data")
    
    abs_path = os.path.abspath(filename)
    print(f"Created {abs_path}")
    
    # 2. Quarantine it BUT log it with different casing (simulate GUI/Input variance)
    # We essentially mock the call to log_quarantine internal logic by modifying the log after quarantine
    
    msg = quarantine_file(abs_path, "Test Threat")
    print(msg)
    
    # Manually mangle the log to have UPPERCASE filename
    with open(QUARANTINE_LOG_FILE, 'r') as f:
        data = json.load(f)
    
    # Provide the path with different casing
    parent = os.path.dirname(abs_path)
    base = os.path.basename(abs_path).upper() # TEST_CASE_BUG.TXT
    mangled_path = os.path.join(parent, base)
    
    data[-1]['original_path'] = mangled_path
    
    with open(QUARANTINE_LOG_FILE, 'w') as f:
        json.dump(data, f, indent=4)
        
    print(f"Mangled Log Path to: {mangled_path}")
    
    # 3. Check Vault file (it should be lowercase or as created)
    # The quarantine_file function likely created it based on the input path (which was correct)
    # Wait, quarantine_file uses os.path.basename(file_path). If input was lowercase, vault file is lowercase.
    
    vault_files = os.listdir(QUARANTINE_DIR)
    print(f"Vault files: {vault_files}")
    
    # 4. Run Sync
    print("Running sync_quarantine_vault()...")
    sync_quarantine_vault()
    
    # 5. Check Log again
    with open(QUARANTINE_LOG_FILE, 'r') as f:
        data = json.load(f)
    
    print(f"Log after sync (Status): {data[-1]['status']}")
    
    if data[-1]['status'] == 'Missing':
        print("[FAIL] Status changed to Missing due to case mismatch!")
    elif data[-1]['status'] == 'Quarantined':
        print("[PASS] Status persisted despite case mismatch.")

    # Cleanup
    # if os.path.exists(vault_path): os.remove(vault_path)

if __name__ == "__main__":
    run_test()
