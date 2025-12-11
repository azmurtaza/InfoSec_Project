
import json
import os
import sys

# Add src to path just in case
sys.path.append('src')
from feature_extraction import extract_pe_features

def validate():
    # Load attributes used in training
    with open('models/features.json', 'r') as f:
        model_features = json.load(f)
        
    print(f"Model expects {len(model_features)} features.")
    
    # Extract features from a real sample
    sample_path = 'data/raw_files/CustomCursor.exe'
    if not os.path.exists(sample_path):
        print(f"[!] Sample file {sample_path} not found. Using dummy check.")
        # If no real file, we can't fully validate runtime extraction without mocking.
        # But we saw CustomCursor.exe in the file list.
        return
        
    extracted_data = extract_pe_features(sample_path)
    
    if extracted_data is None:
        print("[!] Extraction failed.")
        return

    extracted_keys = list(extracted_data.keys())
    print(f"Extractor produced {len(extracted_keys)} features.")
    
    # Compare
    missing_in_extraction = set(model_features) - set(extracted_keys)
    extra_in_extraction = set(extracted_keys) - set(model_features)
    
    if not missing_in_extraction and not extra_in_extraction:
        print("[+] SUCCESS: Feature sets match perfectly!")
    else:
        print("[-] MISMATCH FOUND!")
        if missing_in_extraction:
            print(f"    Missing in extraction: {missing_in_extraction}")
        if extra_in_extraction:
            print(f"    Extra in extraction: {extra_in_extraction}")

if __name__ == "__main__":
    validate()
