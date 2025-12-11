
import pandas as pd
import numpy as np
import joblib
import json
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler, LabelEncoder

def train_model():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(script_dir, '..', 'data', 'dataset.csv')
    
    # Paths for artifacts
    models_dir = os.path.join(script_dir, '..', 'models')
    model_path = os.path.join(models_dir, 'classifier.pkl')
    scaler_path = os.path.join(models_dir, 'scaler.pkl')
    features_path = os.path.join(models_dir, 'features.json')

    if not os.path.exists(models_dir):
        os.makedirs(models_dir)

    print(f"[*] Loading dataset from: {dataset_path}")
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print("[!] Dataset not found!")
        return

    # --- 1. Label Handling ---
    if 'class' in df.columns:
        # Ensure integer
        df['class'] = df['class'].astype(int)
        y = df['class']
        X = df.drop(['class'], axis=1)
    else:
        # Fallback
        print("[!] 'class' column missing, assuming last column is label")
        y = df.iloc[:, -1].astype(int)
        X = df.iloc[:, :-1]
    
    print("Class Balance:")
    print(y.value_counts())

    # --- 2. Non-Numeric Handling & Specific Drops ---
    # We will identify non-numeric columns. 
    # For now, we drop them to ensure we can strictly match them in feature extraction.
    # We also drop 'fileinfo' as it is an undefined feature for extraction.
    cols_to_drop = list(X.select_dtypes(exclude=[np.number]).columns)
    if 'fileinfo' in X.columns:
        cols_to_drop.append('fileinfo')
    
    # Drop duplicates if any
    cols_to_drop = list(set(cols_to_drop))

    if len(cols_to_drop) > 0:
        print(f"[*] The following columns will be dropped: {cols_to_drop}")
        X = X.drop(cols_to_drop, axis=1)

    # --- 3. Missing Values & Hygiene ---
    X = X.fillna(0)
    
    # --- 4. Scaling ---
    print("[*] Scaling features (StandardScaler)...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print(f"[*] Training on {len(X)} samples with {X.shape[1]} features.")

    # --- 5. Train/Test Split ---
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    # --- 6. Train Model ---
    print("[*] Training Random Forest (balanced weights)...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    clf.fit(X_train, y_train)

    # --- 7. Evaluation ---
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print("\n" + "="*30)
    print(f" FINAL ACCURACY: {acc * 100:.2f}%")
    print("="*30)
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malware']))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # --- 8. Save Artifacts ---
    print(f"[*] Saving model artifacts to {models_dir}...")
    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)
    
    # Save feature list
    with open(features_path, 'w') as f:
        json.dump(list(X.columns), f)
        
    print("[*] Done.")

if __name__ == "__main__":
    train_model()