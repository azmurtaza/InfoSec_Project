import pefile
import lief
import numpy as np
import warnings

# Monkeypatch lief exceptions for newer LIEF versions
for attr in ['bad_format', 'bad_file', 'pe_error', 'parser_error', 'read_out_of_bound']:
    if not hasattr(lief, attr):
        setattr(lief, attr, Exception)

# Monkeypatch numpy deprecated types for older Ember
# Suppress FutureWarning for np.bool access if it occurs during check
with warnings.catch_warnings():
    warnings.simplefilter("ignore", category=FutureWarning)
    if not hasattr(np, 'float'):
        np.float = float
    if not hasattr(np, 'bool'):
        np.bool = bool
    if not hasattr(np, 'int'):
        np.int = int

# Suppress LIEF version warnings from Ember
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=UserWarning, module='ember') 
    import ember

import os

class EmberAdapter:
    def __init__(self, feature_version=2):
        self.feature_version = feature_version
        with warnings.catch_warnings():
             warnings.simplefilter("ignore")
             self.extractor = ember.PEFeatureExtractor(feature_version)

    def extract_features(self, file_path):
        """
        Extracts features from a PE file using the Ember library.
        Returns a numpy array of shape (1, 2381).
        """
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
                
            # Embed feature extractor expects raw bytes
            features = self.extractor.feature_vector(file_data)
            
            # Reshape for model input (1 sample, N features)
            return np.array(features).reshape(1, -1)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"[!] Ember extraction failed for {file_path}: {e}")
            return None

if __name__ == "__main__":
    # Test
    target = r"C:\Windows\System32\calc.exe"
    if os.path.exists(target):
        adapter = EmberAdapter()
        feats = adapter.extract_features(target)
        if feats is not None:
            print(f"Extraction successful: {feats.shape}")
        else:
            print("Extraction returned None")
    else:
        print("Calc.exe not found for testing.")
