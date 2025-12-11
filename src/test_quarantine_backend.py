
import os
import json
from quarantine import quarantine_file, restore_file, delete_quarantined_file

TEST_FILE = "dummy_virus.exe"

def create_dummy():
    with open(TEST_FILE, "w") as f:
        f.write("malware bytes")
    print(f"Created {TEST_FILE}")

def run_test():
    # 1. Quarantine
    create_dummy()
    path = os.path.abspath(TEST_FILE)
    print(f"Quarantining {path}...")
    res = quarantine_file(path, "Test Threat")
    print(res)
    
    if os.path.exists(path):
        print("FAIL: File still exists at source!")
    else:
        print("PASS: File moved.")

    # 2. Restore
    print("Restoring...")
    res = restore_file(path)
    print(res)
    
    if os.path.exists(path):
        print("PASS: File restored.")
    else:
        print("FAIL: File not restored!")
        
    # 3. Quarantine & Delete
    print("Quarantining again for delete test...")
    quarantine_file(path, "Test Threat")
    
    print("Deleting...")
    res = delete_quarantined_file(path)
    print(res)
    
    # Check vault
    vault_path = os.path.join("quarantine_vault", "dummy_virus.exe.LOCKED")
    if os.path.exists(vault_path):
        print("FAIL: File still in vault!")
    else:
        print("PASS: File deleted from vault.")
        
    # Cleanup
    if os.path.exists(TEST_FILE):
        os.remove(TEST_FILE)

if __name__ == "__main__":
    run_test()
