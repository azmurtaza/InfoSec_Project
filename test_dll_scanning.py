"""
Test script to verify that DLL files are being scanned properly
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from scanner_engine import MalwareScanner

def test_dll_scanning():
    """Test that the scanner properly handles DLL files"""
    scanner = MalwareScanner()
    
    # Test with a system DLL file
    test_dll = r"C:\Windows\System32\kernel32.dll"
    
    if not os.path.exists(test_dll):
        print(f"[!] Test DLL not found: {test_dll}")
        print("[*] Trying alternative DLL...")
        test_dll = r"C:\Windows\System32\ntdll.dll"
    
    if not os.path.exists(test_dll):
        print("[!] No system DLL found for testing")
        return
    
    print(f"[*] Testing DLL scanning with: {test_dll}")
    print("-" * 60)
    
    try:
        result = scanner.scan_file(test_dll)
        
        if isinstance(result, dict):
            print(f"[+] DLL file scanned successfully!")
            print(f"  Status: {result.get('status', 'unknown')}")
            print(f"  Confidence: {result.get('confidence', 0):.2f}%")
            print(f"  File: {result.get('file_name', 'unknown')}")
            print(f"  Type: {result.get('Type', 'unknown')}")
        else:
            print(f"[-] Unexpected result: {result}")
    except Exception as e:
        print(f"[-] Error scanning DLL: {e}")
        import traceback
        traceback.print_exc()
    
    print("-" * 60)
    print("\n[*] Testing directory scan with DLL files...")
    
    # Test directory scanning
    test_dir = r"C:\Windows\System32"
    dll_count = 0
    
    try:
        for result in scanner.scan_directory(test_dir):
            dll_count += 1
            if dll_count <= 3:  # Show first 3 results
                print(f"  Found threat in: {result.get('file_name', 'unknown')}")
            if dll_count >= 3:
                break
        
        if dll_count == 0:
            print("  [+] No threats found in system DLLs (expected)")
        else:
            print(f"  Found {dll_count} potential threats")
    except Exception as e:
        print(f"  Error during directory scan: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("DLL Scanning Test")
    print("=" * 60)
    test_dll_scanning()
    print("\n[+] Test complete!")
