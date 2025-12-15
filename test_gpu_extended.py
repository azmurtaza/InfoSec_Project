"""
Extended GPU Test for LightGBM
Creates a longer training session so you can observe GPU usage in nvidia-smi
"""

import lightgbm as lgb
import numpy as np
import time
import subprocess

def check_gpu_status():
    """Check current GPU utilization"""
    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=utilization.gpu,memory.used,temperature.gpu', 
             '--format=csv,noheader,nounits'], 
            capture_output=True, text=True
        )
        if result.returncode == 0:
            gpu_util, mem_used, temp = result.stdout.strip().split(',')
            print(f"   GPU Utilization: {gpu_util.strip()}% | Memory: {mem_used.strip()} MB | Temp: {temp.strip()}C")
            return True
    except Exception as e:
        print(f"   Could not read GPU status: {e}")
    return False

print("="*70)
print("Extended GPU Training Test")
print("="*70)
print("\n[INSTRUCTIONS]")
print("1. Open a SECOND terminal window")
print("2. Run this command: nvidia-smi -l 1")
print("3. Watch the GPU utilization spike during training!")
print("\nPress Enter when ready...")
input()

print("\n[*] Creating large dataset for extended GPU test...")
# Larger dataset = longer training time
X = np.random.rand(100000, 100)
y = np.random.randint(0, 2, 100000)

print(f"[*] Dataset shape: {X.shape}")
print(f"[*] Dataset size: ~{X.nbytes / 1024 / 1024:.1f} MB")

train_data = lgb.Dataset(X, label=y)

print("\n[*] GPU status BEFORE training:")
check_gpu_status()

params = {
    'device': 'gpu',
    'gpu_platform_id': 0,
    'gpu_device_id': 0,
    'objective': 'binary',
    'num_leaves': 127,
    'max_depth': 8,
    'n_estimators': 500,  # More trees = longer training
    'learning_rate': 0.05,
    'verbose': 10  # Show progress every 10 iterations
}

print("\n" + "="*70)
print("[*] Starting GPU training...")
print("[*] This will take 30-60 seconds - WATCH nvidia-smi!")
print("="*70)

start = time.time()
clf = lgb.LGBMClassifier(**params)
clf.fit(X, y)
elapsed = time.time() - start

print("\n" + "="*70)
print(f"[SUCCESS] Training completed in {elapsed:.2f} seconds")
print("="*70)

print("\n[*] GPU status AFTER training:")
check_gpu_status()

print("\n" + "="*70)
print("RESULTS")
print("="*70)
print(f"Training time: {elapsed:.2f} seconds")
print("\nDid you see GPU utilization spike in nvidia-smi?")
print("Expected values during training:")
print("  - GPU Utilization: 40-90%")
print("  - GPU Memory: 1000-3000 MB")
print("  - Temperature: 60-75C")
print("\nIf you saw these values, your GPU is working correctly!")
print("="*70)
