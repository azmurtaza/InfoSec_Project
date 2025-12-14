
import pandas as pd
import numpy as np
import joblib
import json
import os
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler, LabelEncoder

def train_model():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(script_dir, '..', 'data', 'dataset.csv')
    new_dataset_path = os.path.join(script_dir, '..', 'data', 'new_dataset.csv')
    
    # Paths for artifacts
    models_dir = os.path.join(script_dir, '..', 'models')
    model_path = os.path.join(models_dir, 'classifier.pkl')
    scaler_path = os.path.join(models_dir, 'scaler.pkl')
    features_path = os.path.join(models_dir, 'features.json')

    if not os.path.exists(models_dir):
        os.makedirs(models_dir)

    # --- Load Hybrid Dataset ---
    dfs = []
    
    # 1. Load Original Dataset
    if os.path.exists(dataset_path):
        print(f"[*] Loading original dataset: {dataset_path}")
        df_old = pd.read_csv(dataset_path)
        dfs.append(df_old)
    else:
        print(f"[!] Original dataset not found at {dataset_path}")

    # 2. Load New Dataset (Byte Features)
    if os.path.exists(new_dataset_path):
        print(f"[*] Loading new dataset: {new_dataset_path}")
        df_new = pd.read_csv(new_dataset_path)
        dfs.append(df_new)
    else:
        print(f"[*] New dataset not found at {new_dataset_path} (skipping)")

    if not dfs:
        print("[!] No datasets found! Exiting.")
        return

    # 3. Merge
    print("[*] Merging datasets...")
    df = pd.concat(dfs, ignore_index=True)
    df = df.fillna(0)

    # --- Feature Selection (Reduce Noise) ---
    # The new_dataset introduces 256+ byte columns but only has 5 rows.
    # The original dataset has 5200 rows without them (so they are 0).
    # This confuses the model. We will drop columns that are predominantly 0/inactive
    # to stick to the robust PE features from the main dataset.
    
    print("[*] Performing Feature Selection (Removing Sparse Features)...")
    threshold = 0.05 # If a feature is non-zero in less than 5% of data, drop it.
    
    # Keep 'class' safe
    labels = df['class'] if 'class' in df.columns else df.iloc[:, -1]
    potential_features = df.drop('class', axis=1) if 'class' in df.columns else df.iloc[:, :-1]
    
    # Calculate non-zero ratio
    non_zeros = (potential_features != 0).sum() / len(potential_features)
    keep_cols = non_zeros[non_zeros > threshold].index.tolist()
    
    # Force keep crucial PE headers if they happen to be 0 (unlikely for many, but safe)
    # Actually, if 'NumberOfSections' is 0 for all, it's useless.
    # So this logic is sound.
    
    # Reconstruct robust DF
    if 'class' in df.columns:
        df = df[keep_cols + ['class']]
    else:
        # If class was mixed in, this might be tricky, but we separated labels above.
        # Safest to just rebuild X and y.
        pass

    y = labels.astype(int)
    X = df[keep_cols]
    
    print(f"[*] Features reduced from {df.shape[1]} to {X.shape[1]}")
    print(f"[*] Kept Features: {list(X.columns)[:10]} ...")

    # --- 1. Label Handling (Already done above) ---
    print("Class Balance:")
    print(y.value_counts())

    # --- 2. Non-Numeric Handling & Specific Drops ---
    cols_to_drop = list(X.select_dtypes(exclude=[np.number]).columns)
    if 'fileinfo' in X.columns:
        cols_to_drop.append('fileinfo')
    
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

    # --- 6. Train Model with Tuning ---
    print("[*] Starting Hyperparameter Tuning (GridSearchCV)...")
    
    # Using RandomForest for better robustness against noise than GradientBoosting sometimes,
    # but sticking to GB as requested earlier.
    param_grid = {
        'n_estimators': [100, 200],
        'learning_rate': [0.1],
        'max_depth': [5],
        'min_samples_split': [5]
    }
    
    base_clf = GradientBoostingClassifier(random_state=42)
    
    grid_search = GridSearchCV(estimator=base_clf, param_grid=param_grid, 
                               cv=3, n_jobs=-1, verbose=1, scoring='accuracy')
    
    grid_search.fit(X_train, y_train)
    
    print("\n" + "="*30)
    print(f" BEST PARAMS: {grid_search.best_params_}")
    print("="*30)
    
    clf = grid_search.best_estimator_

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

    # --- Feature Importance ---
    print("\n[*] Feature Importance Analysis:")
    importances = clf.feature_importances_
    feature_names = X.columns
    
    feature_imp = sorted(zip(importances, feature_names), reverse=True)
    
    print("Top 20 Most Influential Features:")
    for score, name in feature_imp[:20]:
        print(f"   {name}: {score:.4f}")

    # --- 8. Save Artifacts ---
    print(f"\n[*] Saving model artifacts to {models_dir}...")
    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)
    
    # Save feature list
    with open(features_path, 'w') as f:
        json.dump(list(X.columns), f)
        
    print("[*] Done.")

if __name__ == "__main__":
    train_model()