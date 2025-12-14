import pandas as pd
import numpy as np
import joblib
import os
import lightgbm as lgb
from sklearn.metrics import accuracy_score, classification_report
import pyarrow.parquet as pq

def train_ensemble():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, '..', 'data')
    models_dir = os.path.join(script_dir, '..', 'models')
    
    train_path = os.path.join(data_dir, 'train.parquet')
    test_path = os.path.join(data_dir, 'test.parquet')
    
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)

    print("[*] Loading Ember training data from Parquet...")
    df_full = pd.read_parquet(train_path)
    
    # Subsample to manageable size
    MAX_TOTAL = 600000
    if len(df_full) > MAX_TOTAL:
        print(f"[*] Subsampling from {len(df_full)} to {MAX_TOTAL}...")
        df_full = df_full.sample(n=MAX_TOTAL, random_state=42)
    
    target_col = 'Label'
    
    # Load test data once
    print("[*] Loading test data...")
    df_test = pd.read_parquet(test_path)
    y_test = df_test[target_col]
    X_test = df_test.drop(columns=[target_col])
    del df_test
    import gc
    gc.collect()
    
    # Train 3 models on different random subsets
    NUM_MODELS = 3
    CHUNK_SIZE = 200000
    models = []
    
    for model_idx in range(NUM_MODELS):
        print(f"\n{'='*60}")
        print(f"[*] Training Model {model_idx + 1}/{NUM_MODELS}")
        print(f"{'='*60}")
        
        # Create different random sample for each model
        df_train = df_full.sample(n=CHUNK_SIZE, random_state=42 + model_idx)
        
        print(f"[*] Training data shape: {df_train.shape}")
        
        y_train = df_train[target_col]
        X_train = df_train.drop(columns=[target_col])
        del df_train
        gc.collect()
        
        # Train model with optimized params
        print(f"[*] Training LightGBM Model {model_idx + 1}...")
        clf = lgb.LGBMClassifier(
            boosting_type='gbdt',
            n_estimators=200,  # Reduced for faster training
            learning_rate=0.05,
            num_leaves=128,
            max_depth=8,
            min_child_samples=20,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42 + model_idx,
            n_jobs=-1,
            verbose=-1
        )
        
        clf.fit(X_train, y_train)
        
        # Evaluate
        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"[*] Model {model_idx + 1} Accuracy: {acc * 100:.2f}%")
        
        # Save individual model
        model_path = os.path.join(models_dir, f'ensemble_model_{model_idx}.pkl')
        joblib.dump(clf, model_path)
        print(f"[*] Saved to {model_path}")
        
        models.append(clf)
        
        del X_train, y_train
        gc.collect()
    
    # Ensemble prediction (voting)
    print(f"\n{'='*60}")
    print("[*] Evaluating Ensemble (Majority Voting)...")
    print(f"{'='*60}")
    
    ensemble_preds = []
    for clf in models:
        preds = clf.predict(X_test)
        ensemble_preds.append(preds)
    
    # Majority vote
    ensemble_preds = np.array(ensemble_preds)
    final_preds = []
    for i in range(len(X_test)):
        votes = ensemble_preds[:, i]
        # Get most common prediction
        unique, counts = np.unique(votes, return_counts=True)
        final_pred = unique[np.argmax(counts)]
        final_preds.append(final_pred)
    
    final_preds = np.array(final_preds)
    ensemble_acc = accuracy_score(y_test, final_preds)
    
    print(f"\n{'='*60}")
    print(f"ENSEMBLE ACCURACY: {ensemble_acc * 100:.2f}%")
    print(f"{'='*60}")
    print(classification_report(y_test, final_preds))
    
    # Save ensemble wrapper
    ensemble_wrapper = {
        'models': models,
        'num_models': NUM_MODELS
    }
    ensemble_path = os.path.join(models_dir, 'ensemble_classifier.pkl')
    joblib.dump(ensemble_wrapper, ensemble_path)
    print(f"\n[*] Ensemble saved to {ensemble_path}")
    print("[*] Done!")

if __name__ == "__main__":
    train_ensemble()
