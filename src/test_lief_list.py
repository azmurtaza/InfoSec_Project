import lief
import os

target = r"C:\Windows\System32\calc.exe"

try:
    with open(target, 'rb') as f:
        data = f.read()
    
    # Test 1: Bytes
    print("Testing parse(bytes)...")
    try:
        lief.PE.parse(data)
        print("PASS")
    except Exception as e:
        print(f"FAIL: {e}")

    # Test 2: List of Ints
    print("Testing parse(list(int))...")
    data_list = list(data)
    try:
        lief.PE.parse(data_list)
        print("PASS")
    except Exception as e:
        print(f"FAIL: {e}")

except Exception as e:
    print(f"Setup failed: {e}")
