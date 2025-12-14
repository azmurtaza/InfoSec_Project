import sys
sys.path.insert(0, 'src')
from scanner_engine import MalwareScanner

s = MalwareScanner()

print("="*60)
print("MALWARE DETECTION TEST")
print("="*60)

# Test malware files
print("\n[MALWARE FILES]")
malware_files = ['data/raw_files/malware1.exe', 'data/raw_files/virus1.exe']
for f in malware_files:
    result = s.scan_file(f)
    status_icon = "[OK]" if result['status'] == 'malware' else "[FAIL]"
    print(f"{status_icon} {f}: {result['status'].upper()} ({result['confidence']:.2f}%) - {result['Type']}")

# Test benign files
print("\n[BENIGN FILES]")
benign_files = ['data/raw_files/vlc-3.0.21-win32.exe', 'data/raw_files/winrar-x64-713.exe']
for f in benign_files:
    result = s.scan_file(f)
    status_icon = "[OK]" if result['status'] == 'benign' else f"[WARN] {result['status'].upper()}"
    print(f"{status_icon} {f}: {result['status'].upper()} ({result['confidence']:.2f}%) - {result['Type']}")

# Test EICAR
print("\n[TEST FILES]")
result = s.scan_file('test_eicar.txt')
status_icon = "[OK]" if result['status'] == 'malware' and result['confidence'] == 100.0 else "[FAIL]"
print(f"{status_icon} EICAR: {result['status'].upper()} ({result['confidence']:.2f}%) - {result['Type']}")

# Test benign text file
result = s.scan_file('test_benign.txt')
status_icon = "[OK]" if result['status'] == 'benign' else "[FAIL]"
print(f"{status_icon} Benign Text: {result['status'].upper()} ({result['confidence']:.2f}%) - {result['Type']}")

print("\n" + "="*60)
print("TEST COMPLETE")
print("="*60)
