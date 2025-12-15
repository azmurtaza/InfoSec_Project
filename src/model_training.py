
import pandas as pd
import numpy as np
import joblib
import json
import os
import argparse
import lightgbm as lgb
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

def train_model(use_full_dataset=False, max_samples=400000):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, '..', 'data')
    models_dir = os.path.join(script_dir, '..', 'models')
    
    train_path = os.path.join(data_dir, 'train.parquet')
    test_path = os.path.join(data_dir, 'test.parquet')
    
    model_path = os.path.join(models_dir, 'classifier.pkl')
    
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)

    print("[*] Loading Ember training data from Parquet...")
    if not os.path.exists(train_path):
        print(f"[!] Training data not found at {train_path}")
        return

    # Memory-efficient loading strategy
    import pyarrow.parquet as pq
    import pyarrow as pa
    import gc
    
    def load_parquet_optimized(path, use_full=False, max_samples=None):
        """Load parquet with memory optimizations"""
        try:
            print(f"[*] Loading dataset from {path}...")
            
            # Load with pyarrow
            df = pd.read_parquet(path, engine='pyarrow')
            
            print(f"[*] Loaded {len(df):,} samples")
            
            # Memory optimization: Convert float64 to float32 (50% memory reduction)
            print("[*] Optimizing memory usage (float64 → float32)...")
            float_cols = df.select_dtypes(include=['float64']).columns
            df[float_cols] = df[float_cols].astype('float32')
            
            # Subsample if requested and not using full dataset
            if not use_full and max_samples and len(df) > max_samples:
                print(f"[*] Subsampling to {max_samples:,} samples...")
                df = df.sample(n=max_samples, random_state=42)
                gc.collect()
            elif use_full:
                print(f"[*] Using FULL DATASET ({len(df):,} samples)")
            
            return df
            
        except (pa.ArrowMemoryError, MemoryError) as e:
            print(f"[!] Memory error during load: {e}")
            print("[*] Attempting chunked load with aggressive subsampling...")
            
            try:
                parquet_file = pq.ParquetFile(path)
                num_row_groups = parquet_file.num_row_groups
                print(f"[*] Total row groups: {num_row_groups}")
                
                dfs = []
                total_rows = 0
                target_rows = max_samples if not use_full else None
                
                # Load row groups until we reach target
                for i in range(num_row_groups):
                    if target_rows and total_rows >= target_rows:
                        break
                        
                    t = parquet_file.read_row_group(i)
                    df_chunk = t.to_pandas()
                    
                    # Optimize chunk immediately
                    float_cols = df_chunk.select_dtypes(include=['float64']).columns
                    df_chunk[float_cols] = df_chunk[float_cols].astype('float32')
                    
                    dfs.append(df_chunk)
                    total_rows += len(df_chunk)
                    
                    if i % 10 == 0:
                        print(f"[*] Loaded {total_rows:,} rows so far...")
                        
                print(f"[*] Loaded {len(dfs)} chunks ({total_rows:,} rows). Concatenating...")
                df = pd.concat(dfs, ignore_index=True)
                del dfs
                gc.collect()
                return df
                
            except Exception as e2:
                print(f"[!] Chunked load failed: {e2}")
                return None

    # Load training data
    df_train = load_parquet_optimized(train_path, use_full=use_full_dataset, max_samples=max_samples)
    
    if df_train is None:
        print("[!] Critical: Could not load training data.")
        return
    
    print(f"[*] Training dataset size: {len(df_train):,} samples")


    # Handle labels
    target_col = 'label'
    if 'label' not in df_train.columns:
        candidates = [c for c in df_train.columns if 'lab' in c.lower()]
        if candidates:
            target_col = candidates[0]
        else:
            target_col = df_train.columns[-1]
            
    print(f"[*] Identified target column: {target_col}")

    # Filter out unlabeled data (-1)
    print(f"[*] Filtering unlabeled data (label == -1)...")
    initial_len = len(df_train)
    df_train = df_train[df_train[target_col] != -1]
    filtered_len = len(df_train)
    print(f"[*] Removed {initial_len - filtered_len:,} unlabeled samples. Remaining: {filtered_len:,}")
    
    y_train = df_train[target_col].astype('int32')
    X_train = df_train.drop(columns=[target_col])
    
    # Free memory
    del df_train
    gc.collect()

    print(f"[*] Training Data Shape: {X_train.shape}")
    print(f"[*] Features: {X_train.shape[1]}")
    print(f"[*] Class distribution:")
    print(y_train.value_counts())
    
    # Load Test Data
    print("\n[*] Loading test data...")
    if os.path.exists(test_path):
        df_test = pd.read_parquet(test_path, engine='pyarrow')
        
        # Optimize test data too
        float_cols = df_test.select_dtypes(include=['float64']).columns
        df_test[float_cols] = df_test[float_cols].astype('float32')
        
        # Filter unlabeled in test too just in case
        df_test = df_test[df_test[target_col] != -1]
        
        y_test = df_test[target_col].astype('int32')
        X_test = df_test.drop(columns=[target_col])
        del df_test
        gc.collect()
        print(f"[*] Test Data Shape: {X_test.shape}")
    else:
        print("[!] Test data not found. Splitting training data...")
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(
            X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
        )
        print(f"[*] Train split: {X_train.shape}, Test split: {X_test.shape}")

    # --- Train LightGBM ---
    print("\n" + "="*60)
    print("[*] Training LightGBM Model with GPU acceleration (RTX 3050)...")
    print("="*60)
    
    # Optimized configuration for full dataset with GPU
    # Platform 1 is usually NVIDIA on dual-GPU systems
    clf = lgb.LGBMClassifier(
        boosting_type='gbdt',
        device='gpu',  # GPU acceleration
        gpu_platform_id=1,  # Try Platform 1 for NVIDIA
        gpu_device_id=0,
        n_estimators=1000,
        learning_rate=0.05,
        num_leaves=64,       # Reduced to 64 (standard good value)
        max_depth=8,         # Shallower trees to prevent "No further splits"
        min_child_samples=500, # Significantly increased to ensure robust splits
        max_bin=63,          # GPU stability
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=1.0,
        reg_lambda=1.0,
        random_state=42,
        n_jobs=-1,
        verbose=-1           # Suppress "No further splits" warnings
    )
    
    print(f"[*] Training on {len(X_train):,} samples...")
    print("[*] This may take 30-60 minutes depending on your GPU...")
    
    clf.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        eval_metric='binary_logloss',
        callbacks=[
            lgb.log_evaluation(period=50),
            lgb.early_stopping(stopping_rounds=50, verbose=True)
        ]
    )
    
    # Free training data
    del X_train, y_train
    gc.collect()
    
    print("\n[*] Model trained successfully!")
    
    # --- Evaluation ---
    print("\n" + "="*60)
    print("[*] Evaluating model performance...")
    print("="*60)
    
    y_pred = clf.predict(X_test)
    y_pred_proba = clf.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    
    print(f"\n{'='*60}")
    print(f"FINAL ACCURACY: {acc * 100:.2f}%")
    print(f"{'='*60}\n")
    
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malware']))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print(f"\nTrue Negatives: {cm[0][0]:,}")
    print(f"False Positives: {cm[0][1]:,}")
    print(f"False Negatives: {cm[1][0]:,}")
    print(f"True Positives: {cm[1][1]:,}")
    
    # Calculate additional metrics
    from sklearn.metrics import precision_score, recall_score, f1_score
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"\nPrecision: {precision*100:.2f}%")
    print(f"Recall: {recall*100:.2f}%")
    print(f"F1-Score: {f1*100:.2f}%")
    
    # --- Save ---
    print(f"\n[*] Saving model to {model_path}...")
    joblib.dump(clf, model_path)
    
    # Save training metadata
    metadata = {
        'accuracy': float(acc),
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'training_samples': len(y_test) * 5 if use_full_dataset else max_samples,  # Approximate
        'test_samples': len(y_test),
        'features': X_test.shape[1],
        'full_dataset': use_full_dataset
    }
    
    metadata_path = os.path.join(models_dir, 'model_metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"[*] Model metadata saved to {metadata_path}")
    print("\n[✓] Training complete!")
    
    return clf

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Train malware detection model')
    # Default to FULL DATASET as requested
    parser.add_argument('--full-dataset', action='store_true', default=True,
                        help='Train on full dataset (~800k samples)')
    parser.add_argument('--max-samples', type=int, default=1000000,
                        help='Maximum samples to use (default: 1,000,000)')
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("MALWARE DETECTION MODEL TRAINING")
    print("="*60)
    
    # If explicit full-dataset flag or default, use all
    use_full = args.full_dataset
    
    if use_full:
        print("[*] Mode: FULL DATASET (all samples)")
    else:
        print(f"[*] Mode: SUBSAMPLED ({args.max_samples:,} samples)")
    
    print("="*60 + "\n")
    
    train_model(use_full_dataset=use_full, max_samples=args.max_samples)
