"""
Simple GPU Test for LightGBM - No Unicode Characters
"""

import lightgbm as lgb
import numpy as np
import time

print("="*70)
print("LightGBM GPU Support Test")
print("="*70)
print(f"\nLightGBM version: {lgb.__version__}")

# Create sample data
print("\n[*] Creating sample dataset...")
X = np.random.rand(10000, 50)
y = np.random.randint(0, 2, 10000)

train_data = lgb.Dataset(X, label=y)

# Test 1: CPU Training
print("\n" + "="*70)
print("Test 1: CPU Training (Baseline)")
print("="*70)

params_cpu = {
    'device': 'cpu',
    'objective': 'binary',
    'num_leaves': 31,
    'verbose': -1
}

print("[*] Training on CPU...")
start = time.time()
try:
    gbm_cpu = lgb.train(params_cpu, train_data, num_boost_round=100, verbose_eval=False)
    cpu_time = time.time() - start
    print(f"[SUCCESS] CPU training completed in {cpu_time:.2f} seconds")
except Exception as e:
    print(f"[FAILED] CPU training failed: {e}")
    cpu_time = None

# Test 2: GPU Training
print("\n" + "="*70)
print("Test 2: GPU Training")
print("="*70)

params_gpu = {
    'device': 'gpu',
    'gpu_platform_id': 0,
    'gpu_device_id': 0,
    'objective': 'binary',
    'num_leaves': 31,
    'verbose': -1
}

print("[*] Attempting GPU training...")
start = time.time()
try:
    gbm_gpu = lgb.train(params_gpu, train_data, num_boost_round=100, verbose_eval=False)
    gpu_time = time.time() - start
    print(f"[SUCCESS] GPU training completed in {gpu_time:.2f} seconds")
    
    if cpu_time:
        speedup = cpu_time / gpu_time
        print(f"\n[SPEEDUP] GPU is {speedup:.2f}x faster than CPU")
    
    print("\n" + "="*70)
    print("[SUCCESS] GPU ACCELERATION IS WORKING!")
    print("="*70)
    print("\nYour LightGBM is properly configured for GPU training.")
    
except Exception as e:
    print(f"\n[FAILED] GPU training FAILED")
    print(f"Error: {e}")
    print("\n" + "="*70)
    print("[WARNING] GPU ACCELERATION NOT AVAILABLE")
    print("="*70)
    print("\nROOT CAUSE:")
    print("LightGBM was NOT compiled with GPU support.")
    print("\nSOLUTION:")
    print("1. Uninstall current LightGBM:")
    print("   pip uninstall lightgbm -y")
    print("\n2. Install GPU-enabled version:")
    print("   pip install lightgbm --config-settings=cmake.define.USE_GPU=ON")
    print("\n3. Or build from source with GPU support")
    print("\n4. Verify CUDA toolkit is installed")
    print("   Download from: https://developer.nvidia.com/cuda-downloads")

print("\n" + "="*70)
