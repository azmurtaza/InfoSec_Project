import pandas as pd
import numpy as np
import joblib
import json
import os  # <--- Added to fix path issues
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix

def train_model():
    # --- SMART PATH FIX ---
    # This finds the folder where THIS script lives (src)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # This constructs the path: src -> up one level -> data -> dataset.csv
    dataset_path = os.path.join(script_dir, '..', 'data', 'dataset.csv')
    
    print(f"[*] Loading dataset from: {dataset_path}")

    # 1. Load Data
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"[!] Critical Error: Could not find file at {dataset_path}")
        print("    -> Make sure 'dataset.csv' is inside the 'data' folder.")
        return

    # 2. Preprocessing for ClaMP Dataset
    print("[*] Preprocessing data...")
    
    # ClaMP Raw usually uses 'class' column (0=benign, 1=malware)
    if 'class' not in df.columns:
        # Heuristic: If 'class' isn't there, assume the last column is the label
        label_col = df.columns[-1]
        print(f"[*] 'class' column not found. Assuming '{label_col}' is the label.")
        y = df[label_col]
        X = df.drop([label_col], axis=1)
    else:
        y = df['class']
        X = df.drop(['class'], axis=1)

    # Drop non-numeric columns (like filenames or MD5 hashes if they exist)
    X = X.select_dtypes(include=[np.number])
    
    # Fill any empty spots with 0
    X.fillna(0, inplace=True)

    print(f"[*] Training on {len(df)} files with {X.shape[1]} features per file.")

    # 3. Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 4. Train
    print("[*] Training Random Forest... (This builds the brain)")
    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X_train, y_train)

    # 5. Evaluate
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print("\n" + "="*30)
    print(f" RESULTS")
    print("="*30)
    print(f"Accuracy: {acc * 100:.2f}%")
    print("Confusion Matrix (False Positives vs False Negatives):")
    print(confusion_matrix(y_test, y_pred))
    print("="*30)

    # 6. Save Model and Feature List
    # We use the smart path logic again to save into the 'models' folder
    model_path = os.path.join(script_dir, '..', 'models', 'classifier.pkl')
    features_path = os.path.join(script_dir, '..', 'models', 'features.json')

    print(f"[*] Saving model to {model_path}...")
    joblib.dump(clf, model_path)
    
    with open(features_path, 'w') as f:
        json.dump(list(X.columns), f)
        
    print("[*] Done! Ready to scan.")

if __name__ == "__main__":
    train_model()