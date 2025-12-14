
import pandas as pd
import numpy as np
import joblib
import json
import os
import lightgbm as lgb
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

def train_model():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, '..', 'data')
    models_dir = os.path.join(script_dir, '..', 'models')
    
    train_path = os.path.join(data_dir, 'train.parquet')
    test_path = os.path.join(data_dir, 'test.parquet')
    
    model_path = os.path.join(models_dir, 'classifier.pkl')
    # Scaler is not typically needed for Tree-based models like LightGBM, but we can keep the path variable if we need it later.
    
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)

    print("[*] Loading Ember training data from Parquet...")
    if not os.path.exists(train_path):
        print(f"[!] Training data not found at {train_path}")
        return

    # Memory-efficient loading strategy
    import pyarrow.parquet as pq
    import pyarrow as pa
    
    def load_parquet_robust(path):
        try:
            print(f"[*] Attempting full load of {path}...")
            # Use pyarrow engine explicitly
            df = pd.read_parquet(path, engine='pyarrow')
            return df
        except (pa.ArrowMemoryError, MemoryError) as e:
            print(f"[!] Full load failed: {e}")
            print("[*] Attempting chunked load (subsampling)...")
            
            try:
                parquet_file = pq.ParquetFile(path)
                num_row_groups = parquet_file.num_row_groups
                print(f"[*] Total row groups: {num_row_groups}")
                
                # Try loading 50%
                dfs = []
                total_rows = 0
                # Iterate and skip every other group to subsample 50% evenly
                for i in range(0, num_row_groups, 2):
                    t = parquet_file.read_row_group(i)
                    df_chunk = t.to_pandas()
                    dfs.append(df_chunk)
                    total_rows += len(df_chunk)
                    # Safety check on memory - Cap at ~300k samples if tightly constrained (4MB check failed)
                    if total_rows > 300000: 
                        print("[!] Capped at ~300k samples to prevent OOM")
                        break
                        
                print(f"[*] Loaded {len(dfs)} chunks ({total_rows} rows). Concatenating...")
                return pd.concat(dfs, ignore_index=True)
                
            except Exception as e2:
                print(f"[!] Chunked load failed: {e2}")
                return None

    df_train = load_parquet_robust(train_path)
    if df_train is None:
        print("[!] Critical: Could not load training data.")
        return
    
    # AGGRESSIVE SUBSAMPLING TO PREVENT MEMORY CRASH
    MAX_SAMPLES = 400000  # Increased for better accuracy
    if len(df_train) > MAX_SAMPLES:
        print(f"[*] Dataset too large ({len(df_train)}). Subsampling to {MAX_SAMPLES} for memory safety...")
        df_train = df_train.sample(n=MAX_SAMPLES, random_state=42)
        import gc
        gc.collect()

    # Handle labels
    target_col = 'label'
    if 'label' not in df_train.columns:
        candidates = [c for c in df_train.columns if 'lab' in c.lower()]
        if candidates:
            target_col = candidates[0]
        else:
            target_col = df_train.columns[-1]
            
    print(f"[*] Identified target column: {target_col}")

    y_train = df_train[target_col]
    X_train = df_train.drop(columns=[target_col])
    
    # optimize memory
    del df_train
    import gc
    gc.collect()

    print(f"[*] Training Data Shape: {X_train.shape}")
    
    # Load Test Data
    print("[*] Loading Ember test data...")
    if os.path.exists(test_path):
        df_test = pd.read_parquet(test_path)
        y_test = df_test[target_col]
        X_test = df_test.drop(columns=[target_col])
        del df_test
        gc.collect()
    else:
        print("[!] Test data not found. Splitting training data...")
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(X_train, y_train, test_size=0.2, random_state=42)

    # --- Train LightGBM ---
    print("[*] Training LightGBM Model (this may take a while)...")
    
    # Optimized configuration for 95%+ accuracy
    clf = lgb.LGBMClassifier(
        boosting_type='gbdt',
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=128, 
        max_depth=8,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )
    
    clf.fit(X_train, y_train)
    
    print("[*] Model trained.")
    
    # --- Evaluation ---
    print("[*] Evaluating...")
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"FINAL ACCURACY: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred))
    
    # --- Save ---
    print(f"[*] Saving model to {model_path}...")
    joblib.dump(clf, model_path)
    print("[*] Done.")

if __name__ == "__main__":
    train_model()
