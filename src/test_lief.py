import lief
import os

target = r"C:\Windows\System32\calc.exe"

print(f"LIEF Version: {lief.__version__}")

try:
    binary = lief.parse(target)
    if binary:
        print("LIEF parse successful!")
        print(f"Entry point: {binary.entrypoint}")
    else:
        print("LIEF parse returned None")
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"LIEF failed: {e}")

import ember
print(f"Ember imported. Version: {getattr(ember, '__version__', 'unknown')}")
