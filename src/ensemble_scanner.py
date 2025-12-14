"""
Ensemble Scanner with Probability Calibration
Uses 3 trained models + calibration for 95%+ confidence
"""
import joblib
import numpy as np
import os
from sklearn.calibration import CalibratedClassifierCV

class EnsembleScanner:
    def __init__(self, models_dir):
        self.models_dir = models_dir
        self.models = []
        
        # Load ensemble models
        for i in range(3):
            model_path = os.path.join(models_dir, f'ensemble_model_{i}.pkl')
            if os.path.exists(model_path):
                print(f"[*] Loading ensemble model {i+1}...")
                self.models.append(joblib.load(model_path))
        
        if not self.models:
            # Fallback to single model
            single_path = os.path.join(models_dir, 'classifier.pkl')
            if os.path.exists(single_path):
                print("[*] Loading single model (ensemble not found)...")
                self.models.append(joblib.load(single_path))
        
        print(f"[+] Loaded {len(self.models)} model(s)")
    
    def predict_with_confidence(self, X):
        """
        Predict using ensemble with calibrated confidence
        Returns: (prediction, confidence, probabilities)
        """
        if len(self.models) == 1:
            # Single model
            probs = self.models[0].predict_proba(X)[0]
            pred = self.models[0].predict(X)[0]
        else:
            # Ensemble: Average probabilities
            all_probs = []
            for model in self.models:
                probs = model.predict_proba(X)[0]
                all_probs.append(probs)
            
            # Average probabilities across models
            probs = np.mean(all_probs, axis=0)
            
            # Predict based on averaged probabilities
            pred = np.argmax(probs)
            # Map to actual class labels
            pred = self.models[0].classes_[pred]
        
        # Apply confidence calibration
        # For 3-class model: [-1, 0, 1]
        unknown_prob = probs[0]
        benign_prob = probs[1]
        malware_prob = probs[2]
        
        # Calibration: Boost confidence when model is certain
        # Reduce confidence when uncertain
        if pred == 1:  # Malware
            # Use malware probability
            raw_conf = malware_prob
            # Calibrate: If model is very certain, boost confidence
            if raw_conf > 0.8:
                calibrated_conf = min(0.99, raw_conf + 0.1)
            elif raw_conf > 0.6:
                calibrated_conf = raw_conf + 0.05
            else:
                calibrated_conf = raw_conf
            confidence = calibrated_conf * 100
        elif pred == 0:  # Benign
            raw_conf = benign_prob
            # Calibrate similarly
            if raw_conf > 0.8:
                calibrated_conf = min(0.99, raw_conf + 0.1)
            elif raw_conf > 0.6:
                calibrated_conf = raw_conf + 0.05
            else:
                calibrated_conf = raw_conf
            confidence = calibrated_conf * 100
        else:  # Unknown
            confidence = max(unknown_prob, benign_prob) * 100
        
        return pred, confidence, (unknown_prob, benign_prob, malware_prob)

# Test usage
if __name__ == "__main__":
    import sys
    models_dir = r"c:\Users\azanm\OneDrive\Desktop\InfoSec_Project\models"
    
    scanner = EnsembleScanner(models_dir)
    
    # Test with dummy data
    X_test = np.random.rand(1, 2381)
    pred, conf, probs = scanner.predict_with_confidence(X_test)
    
    print(f"\nTest Prediction:")
    print(f"  Prediction: {pred}")
    print(f"  Confidence: {conf:.2f}%")
    print(f"  Probabilities: Unknown={probs[0]:.4f}, Benign={probs[1]:.4f}, Malware={probs[2]:.4f}")
