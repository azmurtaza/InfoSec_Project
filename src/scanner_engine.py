import joblib
import json
import os
import pandas as pd
import feature_extraction

class MalwareScanner:
    def __init__(self):
        # 1. Smart Path Finding (Like before)
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(self.script_dir, '..', 'models', 'classifier.pkl')
        self.features_path = os.path.join(self.script_dir, '..', 'models', 'features.json')
        
        # 2. Load the Brain and the "Memory" (Feature List)
        print(f"[*] Loading model from {self.model_path}...")
        try:
            self.model = joblib.load(self.model_path)
            
            # Load Scaler
            scaler_path = os.path.join(self.script_dir, '..', 'models', 'scaler.pkl')
            self.scaler = joblib.load(scaler_path)
            
            with open(self.features_path, 'r') as f:
                self.features_list = json.load(f)
            print("[+] Model and Scaler loaded successfully!")
        except Exception as e:
            print(f"[!] Critical Error loading model/scaler: {e}")
            self.model = None
            self.scaler = None

    def scan_file(self, file_path):
        if not self.model or not self.scaler:
            return "Error: Model or Scaler not loaded."

        if not os.path.exists(file_path):
            return "Error: File not found."

        # 1. Extract Features (The Eyes)
        print(f"[*] Extracting features from: {os.path.basename(file_path)}")
        data = feature_extraction.extract_pe_features(file_path)
        
        if data is None:
            return "Error: Not a valid PE file (Is this a Windows executable?)"

        # 2. Align Features (The Bridge) - CRITICAL STEP
        # The model expects exactly 68 columns in a specific order.
        # If the file has extra data, ignore it. If missing data, fill with 0.
        
        input_data = {}
        for feature in self.features_list:
            # Get the value if it exists, otherwise 0
            input_data[feature] = data.get(feature, 0)
            
        # Convert to DataFrame (Single row)
        df = pd.DataFrame([input_data])
        
        # 3. Scale Data (CRITICAL FIX)
        # We must scale the data exactly like we did during training!
        try:
            X_scaled = self.scaler.transform(df)
        except Exception as e:
            print(f"[!] Warning: Scaler transform failed ({e}). Predictions might be inaccurate.")
            X_scaled = df

        # 4. Predict (The Brain)
        prediction = self.model.predict(X_scaled)[0] # 0 = Benign, 1 = Malware
        
        try:
            # Fix: Use the maximum probability (confidence in the specific prediction)
            # transform is already applied above
            probs = self.model.predict_proba(X_scaled)[0]
            confidence = max(probs) * 100
        except:
            confidence = 100.0 # Fallback

        # 5. Result Construction
        threat_details = self.get_threat_details(input_data, prediction, confidence)
        
        result = {
            "status": "malware" if prediction == 1 else "benign",
            "confidence": confidence,
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "Type": threat_details['Type'],
            "Severity": threat_details['Severity'],
            "Protocol": threat_details['Protocol'],
            # Backwards compatibility for GUI
            "message": f"{threat_details['Type']} Detected! ({confidence:.2f}%)" if prediction == 1 else "Safe File",
            "recommendation": threat_details['Protocol'] 
        }
            
        return result


    def get_threat_details(self, features, prediction, confidence):
        """
        Analyzes features to classify the threat type and severity.
        """
        if prediction == 0:
            return {
                "Type": "Clean",
                "Severity": "Safe",
                "Protocol": "None"
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
        severity = "Critical" if confidence > 90 else "High"
        
        return {
            "Type": threat_type,
            "Severity": severity,
            "Protocol": pass_protocol
        }



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