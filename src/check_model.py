
import joblib
import os
import sys

try:
    model_path = r"c:\Users\azanm\OneDrive\Desktop\InfoSec_Project\models\classifier.pkl"
    if not os.path.exists(model_path):
        print("Model not found.")
        sys.exit(0)

    clf = joblib.load(model_path)
    print(f"Model Type: {type(clf)}")
    
    if hasattr(clf, 'n_features_in_'):
        print(f"n_features_in_: {clf.n_features_in_}")
    elif hasattr(clf, 'n_features_'):
        print(f"n_features_: {clf.n_features_}")
    else:
        print("Feature count attribute not found (maybe LightGBM specific?)")
        if hasattr(clf, 'booster_'):
             print(f"LightGBM Booster found. Num feature: {clf.booster_.num_feature()}")

except Exception as e:
    print(f"Error: {e}")
