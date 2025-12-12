import os
import time
import shutil
import unittest.mock
from realtime_protection import RealTimeProtector, RealTimeHandler

# Mock callback
def mock_callback(result):
    print(f"\n[TEST] Callback Triggered! Result: {result}")

def test_realtime():
    print("--- Testing Realtime Protection ---")
    
    # Setup
    test_dir = os.path.join(os.path.expanduser("~"), "Downloads")
    
    # Patch MalwareScanner in the module where it is used
    with unittest.mock.patch('realtime_protection.MalwareScanner') as MockScanner:
        # Configure the mock to return a clean result for safe file
        # and a malware result for the other
        mock_instance = MockScanner.return_value
        
        def side_effect(path):
            if "test_malware" in path:
                return {"status": "malware", "confidence": 99.9, "file_path": path, "Type": "TestThreat"}
            else:
                return {"status": "benign", "confidence": 0.0, "file_path": path}
        
        mock_instance.scan_file.side_effect = side_effect
        
        protector = RealTimeProtector(mock_callback)
        
        # Override watch path for safety if needed, but the code uses Downloads
        print(f"Watching: {protector.watch_path}")
        
        protector.start()
        
        # Give it a moment to start
        time.sleep(1)
        
        # 1. Create a BENIGN file
        benign_file = os.path.join(test_dir, "test_safe.exe")
        print(f"Creating benign file: {benign_file}")
        with open(benign_file, "w") as f:
            f.write("This is a safe file.")
        
        time.sleep(1.5) # Wait for event
        
        # 2. Create a MALWARE file
        malware_file = os.path.join(test_dir, "test_malware.exe")
        print(f"Creating malware file: {malware_file}")
        with open(malware_file, "w") as f:
             f.write("malware simulator")

        time.sleep(1.5) # Wait for event and scan
        
        # Cleanup
        protector.stop()
        
        if os.path.exists(benign_file):
            os.remove(benign_file)
        if os.path.exists(malware_file):
            os.remove(malware_file)
        
    print("--- Test Finished ---")

if __name__ == "__main__":
    test_realtime()
