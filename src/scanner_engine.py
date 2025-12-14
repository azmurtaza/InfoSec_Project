import joblib
import json
import os
import pandas as pd
import feature_extraction

import hashlib

class MalwareScanner:
    def __init__(self):
        # 1. Path Setup
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(self.script_dir, '..', 'models', 'classifier.pkl')
        
        # Blacklist (SHA256 hashes of known malware)
        self.BLACKLIST = {
            "cf8bd9dfddff007f75adf4c2be48005deb30972b522858b5404113aa09673225", # EICAR Test File
        }
        
        self.EICAR_STRING = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        
        # 2. Load the Brain (LightGBM Model)
        print(f"[*] Loading model from {self.model_path}...")
        try:
            self.model = joblib.load(self.model_path)
            
            # Setup Ember Adapter
            from ember_adapter import EmberAdapter
            self.adapter = EmberAdapter()
            
            print("[+] Model and Ember Adapter loaded successfully!")
        except Exception as e:
            print(f"[!] Critical Error loading model: {e}")
            self.model = None

    def calculate_file_hash(self, file_path):
        """Calculates SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read and update hash string value in blocks of 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return None

    def scan_file(self, file_path):
        if not self.model:
            return "Error: Model not loaded."

        if not os.path.exists(file_path):
            return "Error: File not found."
            
        # 0. Check Blacklist (Instant Fail)
        file_hash = self.calculate_file_hash(file_path)
        if file_hash in self.BLACKLIST:
             print(f"[!] BLACKLIST MATCH: {os.path.basename(file_path)}")
             return {
                "status": "malware",
                "confidence": 100.0,
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "Type": "Known Signature (Blacklist)",
                "Severity": "Critical",
                "Protocol": "Example Threat Detected",
                "message": "Known Threat Detected! (100.00%)",
                "recommendation": "Immediate Quarantine"
            }

        # 0.5 Check EICAR String Content (Logic Fallback)
        try:
            with open(file_path, 'rb') as f:
                content = f.read(128) # EICAR is short
                if self.EICAR_STRING in content:
                     print(f"[!] EICAR SIGNATURE MATCH: {os.path.basename(file_path)}")
                     return {
                        "status": "malware",
                        "confidence": 100.0,
                        "file_path": file_path,
                        "file_name": os.path.basename(file_path),
                        "Type": "EICAR Test File",
                        "Severity": "Critical",
                        "Protocol": "Test File Detected",
                        "message": "EICAR Test File Detected! (100.00%)",
                        "recommendation": "Delete"
                    }
        except:
             pass

        # 1. Extract Features (The Eyes) - Using Ember Adapter
        print(f"[*] Extracting EMBER features from: {os.path.basename(file_path)}")
        
        # Metadata for heuristics (Legacy extraction)
        metadata = feature_extraction.extract_pe_features(file_path) or {}

        try:
            # We use the adapter to get the (1, 2381) vector
            X_input = self.adapter.extract_features(file_path)
            
            if X_input is None:
                raise ValueError("Feature extraction returned None")
                
        except Exception as e:
            # Fallback for non-PE files or errors
            # CRITICAL: Check file extension - .exe/.dll MUST go through ML
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext in ['.exe', '.dll', '.sys', '.scr', '.com']:
                # Check for signature using legacy metadata to avoid False Positives
                if metadata.get('has_signature', 0) == 1:
                     print(f"[*] Extraction failed but valid signature found for {os.path.basename(file_path)}.")
                     return {
                        "status": "benign",
                        "confidence": 0.0,
                        "file_path": file_path,
                        "file_name": os.path.basename(file_path),
                        "Type": "Clean (Signed/Failed Parse)",
                        "Severity": "Safe",
                        "Protocol": "None",
                        "message": "Safe File (Signed)",
                        "recommendation": "None"
                    }
                
                return {
                        "status": "malware",
                        "confidence": 99.0,
                        "file_path": file_path,
                        "file_name": os.path.basename(file_path),
                        "Type": "Suspicious Executable (Failed Parse)",
                        "Severity": "High",
                        "Protocol": "Quarantine Immediately",
                        "message": f"Malformed/Packed Executable Detected",
                        "recommendation": "Immediate Quarantine"
                    }
            else:
                return {
                        "status": "benign",
                        "confidence": 0.0,
                        "file_path": file_path,
                        "file_name": os.path.basename(file_path),
                        "Type": "Clean",
                        "Severity": "Safe",
                        "Protocol": "None",
                        "message": "Skipped (Not an executable file)",
                        "recommendation": "None"
                    }

        # 4. Predict (The Brain) - No scaling needed for Ember/LightGBM usually, or model has it built-in if pipeline used
        # Ideally LightGBM handles it.
        
        try:
            probs = self.model.predict_proba(X_input)[0]
            
            # CRITICAL: Model has 3 classes: [-1 (unknown), 0 (benign), 1 (malware)]
            # probs[0] = P(class=-1), probs[1] = P(class=0), probs[2] = P(class=1)
            unknown_prob = probs[0] * 100
            benign_prob = probs[1] * 100
            malware_prob = probs[2] * 100
            
            # Use actual prediction from model
            pred_class = self.model.predict(X_input)[0]
            
            # Determine status based on prediction and confidence
            if pred_class == 1:  # Malware
                if malware_prob > 70:
                    prediction = 1
                    confidence = malware_prob
                    status = "malware"
                elif malware_prob > 50:
                    prediction = 1
                    confidence = malware_prob
                    status = "suspicious"
                else:
                    # Low confidence malware - treat as suspicious
                    prediction = 0
                    confidence = benign_prob
                    status = "benign"
            elif pred_class == 0:  # Benign
                prediction = 0
                confidence = benign_prob
                status = "benign"
            else:  # Unknown (-1)
                # Treat unknown as benign with low confidence
                prediction = 0
                confidence = max(benign_prob, unknown_prob)
                status = "benign"
                
        except Exception as e:
            print(f"[!] Prediction Error: {e}")
            return "Error: Prediction failed."

        # 5. Result Construction
        gui_status = "benign" if status == "benign" else "malware"
        
        threat_details = self.get_threat_details(metadata, prediction, confidence, status)
        
        result = {
            "status": gui_status,
            "confidence": confidence,
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "Type": threat_details['Type'],
            "Severity": threat_details['Severity'],
            "Protocol": threat_details['Protocol'],
            "message": f"{threat_details['Type']} Detected! ({confidence:.2f}%)" if gui_status == "malware" else "Safe File",
            "recommendation": threat_details['Protocol'] 
        }
        
        return result


    def get_threat_details(self, features, prediction, confidence, status="malware"):
        """
        Analyzes features to classify the threat type and severity.
        """
        if prediction == 0 and status == "benign":
            return {
                "Type": "Clean",
                "Severity": "Safe",
                "Protocol": "None"
            }

        if status == "suspicious":
            return {
                "Type": "Suspicious / Low Confidence",
                "Severity": "Medium",
                "Protocol": "Manual Scan Recommended"
            }
        
        # Extract features for heuristic analysis
        # Note: We pass the 'features' dict (input_data) here which contains the single file features
        return self.determine_malware_type(features, confidence)

    def determine_malware_type(self, features, confidence):
        sus_sections = features.get('sus_sections', 0)
        filesize = features.get('filesize', 0)
        e_text = features.get('E_text', 0)
        num_sections = features.get('NumberOfSections', 0)
        
        # New Heuristic Features
        suspicious_strings = features.get('Suspicious_Strings', 0)
        resource_entropy = features.get('Resource_Entropy', 0)
        iat_count = features.get('IAT_Count', 0)
        
        threat_type = "Generic Malware"
        pass_protocol = "Isolate file and move to Quarantine"

        # Prioritize Logic
        if e_text > 7.2 or resource_entropy > 7.5:
            threat_type = "Ransomware/Encrypted"
            pass_protocol = "Immediate Quarantine Required (High Entropy)"
        elif suspicious_strings > 2:
            threat_type = "Trojan/Botnet (Suspicious Strings)"
            pass_protocol = "Block Network Access & Quarantine"
        elif num_sections < 4 and filesize > 500 * 1024: 
            threat_type = "Worm/Dropper"
            pass_protocol = "Quarantine and Inspect Payload"
        elif iat_count < 10 and filesize > 100 * 1024:
             threat_type = "Packed Malware (Low Imports)"
             pass_protocol = "Unpack in Sandbox"
        elif sus_sections > 0:
            threat_type = "Trojan/Packer"
            
        # Severity Logic
        severity = "Critical" if confidence > 95 else "High"
        
        return {
            "Type": threat_type,
            "Severity": severity,
            "Protocol": pass_protocol
        }

    def scan_directory(self, directory, callback=None):
        """
        Scans all PE files in a directory.
        Yields result dictionaries for threats found.
        """
        if not os.path.exists(directory):
            return

        print(f"[*] Scanning Directory: {directory}")
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                # Filter for PE files (extensions)
                if file.lower().endswith(('.exe', '.dll', '.sys')):
                    if callback:
                        callback(file_path) # Notify what we are scanning
                    
                    try:
                        result = self.scan_file(file_path)
                        if isinstance(result, dict) and result['status'] == 'malware':
                            yield result
                    except Exception as e:
                        print(f"[!] Error scanning {file_path}: {e}")



# --- TEST AREA (Runs only if you run this file directly) ---
if __name__ == "__main__":
    scanner = MalwareScanner()
    
    # Test on a safe Windows system file or dummy
    test_file = r"C:\Windows\System32\calc.exe"
    if not os.path.exists(test_file):
         test_file = "src/scanner_engine.py" # fallback
    
    print("\n--- TEST SCAN ---")
    result = scanner.scan_file(test_file)
    print(f"Result: {result}")