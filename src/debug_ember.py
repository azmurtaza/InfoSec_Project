
import pefile
import lief
import numpy as np

# Monkeypatch lief exceptions
for attr in ['bad_format', 'bad_file', 'pe_error', 'parser_error', 'read_out_of_bound']:
    if not hasattr(lief, attr):
        setattr(lief, attr, Exception)

# Monkeypatch numpy types
if not hasattr(np, 'float'):
    np.float = float
if not hasattr(np, 'bool'):
    np.bool = bool
if not hasattr(np, 'int'):
    np.int = int

import ember
import traceback
import sys

log_file = "debug_error.txt"

def log(msg):
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

try:
    log("Starting debug...")
    
    target = r"C:\Windows\System32\calc.exe"
    with open(target, "rb") as f:
        file_data = f.read()
    
    log(f"Read {len(file_data)} bytes.")

    log("Instantiating PEFeatureExtractor...")
    extractor = ember.PEFeatureExtractor(2)
    log("PEFeatureExtractor instantiated.")

    log("Extracting features...")
    features = extractor.feature_vector(file_data)
    log(f"Features extracted: {features}")

except BaseException as e:
    log("EXCEPTION CAUGHT:")
    with open(log_file, "a", encoding="utf-8") as f:
        traceback.print_exc(file=f)

log("Done.")
