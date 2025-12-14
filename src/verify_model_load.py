
import joblib
import numpy as np
import os
import sys

def verify():
    model_path = r"c:\Users\azanm\OneDrive\Desktop\InfoSec_Project\models\classifier.pkl"
    if not os.path.exists(model_path):
        print("Model file not found yet.")
        return

    try:
        print(f"Loading model from {model_path}...")
        clf = joblib.load(model_path)
        print("Model loaded successfully.")
        
        print(f"Loaded params: {clf.get_params()}")
        
        # Test prediction with dummy data (Ember features size is 2381)
        dummy_input = np.random.rand(1, 2381)
        print("Running dummy prediction...")
        
        prob = clf.predict_proba(dummy_input)[0]
        pred = clf.predict(dummy_input)[0]
        
        print(f"Prediction: {pred}")
        print(f"Probabilities: {prob}")
        print("Verification SUCCESS.")
        
    except Exception as e:
        print(f"Verification FAILED: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    verify()
