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
            with open(self.features_path, 'r') as f:
                self.features_list = json.load(f)
            print("[+] Model loaded successfully!")
        except Exception as e:
            print(f"[!] Critical Error loading model: {e}")
            self.model = None

    def scan_file(self, file_path):
        if not self.model:
            return "Error: Model not loaded."

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
            scaler_path = os.path.join(self.script_dir, '..', 'models', 'scaler.pkl')
            scaler = joblib.load(scaler_path)
            X_scaled = scaler.transform(df)
        except Exception as e:
            print(f"[!] Warning: Could not load scaler ({e}). Predictions might be inaccurate.")
            X_scaled = df

        # 4. Predict (The Brain)
        prediction = self.model.predict(X_scaled)[0] # 0 = Benign, 1 = Malware
        
        try:
            confidence = self.model.predict_proba(X_scaled)[0][1] * 100 
        except:
            confidence = 100.0 if prediction == 1 else 0.0

        # 5. Result
        result = {
            "status": "malware" if prediction == 1 else "benign",
            "confidence": confidence,
            "file_path": file_path,
            "file_name": os.path.basename(file_path), 
            "message": ""
        }
        
        if prediction == 1:
            result["message"] = f"MALWARE DETECTED! (Confidence: {confidence:.2f}%)"
            result["recommendation"] = "Quarantine" if confidence > 90 else "Delete"
        else:
            final_conf = 100 - confidence
            result["message"] = f"Safe File. (Confidence: {final_conf:.2f}%)"
            result["recommendation"] = "None"
            
        return result

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