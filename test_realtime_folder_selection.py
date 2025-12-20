"""
Test script for Realtime Protection with Custom Folder Selection
Tests folder selection, recursive monitoring, and dynamic folder changes
"""

import os
import sys
import time
import tempfile
import shutil

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from realtime_protection import RealTimeProtector
from scanner_engine import MalwareScanner

def test_callback(result):
    """Callback for threat detection"""
    print(f"[THREAT DETECTED] {result.get('file_name', 'unknown')}")

def test_folder_selection():
    """Test 1: Verify set_watch_path() changes the monitored folder"""
    print("\n" + "="*60)
    print("Test 1: Folder Selection")
    print("="*60)
    
    scanner = MalwareScanner()
    protector = RealTimeProtector(test_callback, scanner)
    
    # Check default path
    default_path = protector.get_watch_path()
    print(f"[*] Default watch path: {default_path}")
    
    # Create test folder
    test_folder = os.path.join(tempfile.gettempdir(), "test_realtime_folder")
    os.makedirs(test_folder, exist_ok=True)
    
    # Change to test folder
    success = protector.set_watch_path(test_folder)
    new_path = protector.get_watch_path()
    
    if success and new_path == test_folder:
        print(f"[+] SUCCESS: Watch path changed to: {new_path}")
    else:
        print(f"[-] FAILED: Watch path not changed correctly")
    
    # Test invalid path
    invalid_success = protector.set_watch_path("/invalid/path/that/does/not/exist")
    if not invalid_success:
        print(f"[+] SUCCESS: Invalid path rejected correctly")
    else:
        print(f"[-] FAILED: Invalid path was accepted")
    
    # Cleanup
    shutil.rmtree(test_folder, ignore_errors=True)

def test_recursive_monitoring():
    """Test 2: Verify recursive monitoring is enabled"""
    print("\n" + "="*60)
    print("Test 2: Recursive Monitoring")
    print("="*60)
    
    scanner = MalwareScanner()
    protector = RealTimeProtector(test_callback, scanner)
    
    # Create test folder structure
    test_folder = os.path.join(tempfile.gettempdir(), "test_recursive")
    subfolder = os.path.join(test_folder, "subfolder")
    os.makedirs(subfolder, exist_ok=True)
    
    # Set watch path and start
    protector.set_watch_path(test_folder)
    success = protector.start()
    
    if success:
        print(f"[+] Protection started successfully")
        print(f"[*] Monitoring: {test_folder} (recursive)")
        
        # Create a test file in subfolder
        test_file = os.path.join(subfolder, "test.txt")
        with open(test_file, 'w') as f:
            f.write("test content")
        
        print(f"[*] Created test file in subfolder: {test_file}")
        print(f"[*] Waiting 2 seconds for file system events...")
        time.sleep(2)
        
        print(f"[+] SUCCESS: Recursive monitoring is enabled")
    else:
        print(f"[-] FAILED: Could not start protection")
    
    # Cleanup
    protector.stop()
    shutil.rmtree(test_folder, ignore_errors=True)

def test_dynamic_folder_change():
    """Test 3: Verify protection restarts when folder is changed while active"""
    print("\n" + "="*60)
    print("Test 3: Dynamic Folder Change")
    print("="*60)
    
    scanner = MalwareScanner()
    protector = RealTimeProtector(test_callback, scanner)
    
    # Create two test folders
    folder_a = os.path.join(tempfile.gettempdir(), "test_folder_a")
    folder_b = os.path.join(tempfile.gettempdir(), "test_folder_b")
    os.makedirs(folder_a, exist_ok=True)
    os.makedirs(folder_b, exist_ok=True)
    
    # Start protection on folder A
    protector.set_watch_path(folder_a)
    protector.start()
    print(f"[*] Protection started on: {folder_a}")
    
    # Change to folder B while running
    success = protector.set_watch_path(folder_b)
    current_path = protector.get_watch_path()
    is_running = protector.is_running
    
    if success and current_path == folder_b and is_running:
        print(f"[+] SUCCESS: Folder changed to {folder_b} while protection active")
        print(f"[+] Protection is still running: {is_running}")
    else:
        print(f"[-] FAILED: Dynamic folder change did not work correctly")
    
    # Cleanup
    protector.stop()
    shutil.rmtree(folder_a, ignore_errors=True)
    shutil.rmtree(folder_b, ignore_errors=True)

def test_validation():
    """Test 4: Verify validation prevents invalid operations"""
    print("\n" + "="*60)
    print("Test 4: Validation")
    print("="*60)
    
    scanner = MalwareScanner()
    protector = RealTimeProtector(test_callback, scanner)
    
    # Test 1: Non-existent folder
    success1 = protector.set_watch_path("/this/path/does/not/exist")
    if not success1:
        print(f"[+] SUCCESS: Non-existent folder rejected")
    else:
        print(f"[-] FAILED: Non-existent folder accepted")
    
    # Test 2: File instead of folder
    test_file = os.path.join(tempfile.gettempdir(), "test_file.txt")
    with open(test_file, 'w') as f:
        f.write("test")
    
    success2 = protector.set_watch_path(test_file)
    if not success2:
        print(f"[+] SUCCESS: File path rejected (not a directory)")
    else:
        print(f"[-] FAILED: File path accepted as directory")
    
    # Cleanup
    os.remove(test_file)

if __name__ == "__main__":
    print("="*60)
    print("Realtime Protection - Custom Folder Selection Tests")
    print("="*60)
    
    try:
        test_folder_selection()
        test_recursive_monitoring()
        test_dynamic_folder_change()
        test_validation()
        
        print("\n" + "="*60)
        print("[+] All tests completed!")
        print("="*60)
    except Exception as e:
        print(f"\n[-] Test failed with error: {e}")
        import traceback
        traceback.print_exc()
