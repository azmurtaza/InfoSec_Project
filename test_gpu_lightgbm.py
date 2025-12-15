"""
Comprehensive GPU Test for LightGBM
Tests if LightGBM can actually use GPU for training
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
    print(f"✓ CPU training completed in {cpu_time:.2f} seconds")
except Exception as e:
    print(f"✗ CPU training failed: {e}")
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
    print(f"✓ GPU training completed in {gpu_time:.2f} seconds")
    
    if cpu_time:
        speedup = cpu_time / gpu_time
        print(f"\n🚀 GPU Speedup: {speedup:.2f}x faster than CPU")
    
    print("\n" + "="*70)
    print("✓ GPU ACCELERATION IS WORKING!")
    print("="*70)
    print("\nYour LightGBM is properly configured for GPU training.")
    print("The model_training.py script should use GPU automatically.")
    
except Exception as e:
    print(f"\n✗ GPU training FAILED: {e}")
    print("\n" + "="*70)
    print("⚠ GPU ACCELERATION NOT AVAILABLE")
    print("="*70)
    print("\nROOT CAUSE:")
    print("LightGBM was NOT compiled with GPU support.")
    print("\nSOLUTION:")
    print("1. Uninstall current LightGBM:")
    print("   pip uninstall lightgbm -y")
    print("\n2. Install GPU-enabled version:")
    print("   pip install lightgbm --config-settings=cmake.define.USE_GPU=ON")
    print("\n   OR build from source:")
    print("   git clone --recursive https://github.com/microsoft/LightGBM")
    print("   cd LightGBM")
    print("   pip install . --config-settings=cmake.define.USE_GPU=ON")
    print("\n3. Verify CUDA toolkit is installed (required for GPU support)")
    print("   Download from: https://developer.nvidia.com/cuda-downloads")

print("\n" + "="*70)
