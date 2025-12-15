"""
GPU Availability Checker for LightGBM
Verifies CUDA installation and GPU support
"""

import sys
import subprocess

def check_nvidia_gpu():
    """Check if NVIDIA GPU is available"""
    try:
        result = subprocess.run(['nvidia-smi'], capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ NVIDIA GPU detected")
            print(result.stdout)
            return True
        else:
            print("✗ nvidia-smi failed")
            return False
    except FileNotFoundError:
        print("✗ nvidia-smi not found (NVIDIA drivers not installed)")
        return False

def check_lightgbm_gpu():
    """Check if LightGBM can use GPU"""
    try:
        import lightgbm as lgb
        print(f"✓ LightGBM version: {lgb.__version__}")
        
        # Try to create a GPU-enabled dataset
        import numpy as np
        X = np.random.rand(100, 10)
        y = np.random.randint(0, 2, 100)
        
        train_data = lgb.Dataset(X, label=y)
        
        params = {
            'device': 'gpu',
            'gpu_platform_id': 0,
            'gpu_device_id': 0,
            'objective': 'binary',
            'verbosity': -1
        }
        
        print("[*] Testing GPU training...")
        try:
            gbm = lgb.train(params, train_data, num_boost_round=10, verbose_eval=False)
            print("✓ GPU training successful!")
            return True
        except Exception as e:
            print(f"✗ GPU training failed: {e}")
            print("\n[!] This likely means LightGBM was not compiled with GPU support.")
            print("[!] You may need to install: pip install lightgbm --install-option=--gpu")
            return False
            
    except ImportError as e:
        print(f"✗ LightGBM not installed: {e}")
        return False

def main():
    print("="*60)
    print("GPU Availability Check for Malware Detection Project")
    print("="*60)
    print()
    
    gpu_available = check_nvidia_gpu()
    print()
    
    if gpu_available:
        lgb_gpu = check_lightgbm_gpu()
        print()
        
        if lgb_gpu:
            print("="*60)
            print("✓ GPU ACCELERATION READY!")
            print("="*60)
            print("\nYou can now use device='gpu' in your LightGBM models.")
        else:
            print("="*60)
            print("⚠ GPU detected but LightGBM GPU support not available")
            print("="*60)
            print("\nRecommended action:")
            print("1. Uninstall current LightGBM: pip uninstall lightgbm")
            print("2. Install GPU version: pip install lightgbm --config-settings=cmake.define.USE_GPU=ON")
    else:
        print("="*60)
        print("✗ No NVIDIA GPU detected")
        print("="*60)

if __name__ == "__main__":
    main()
