"""
GPU-Enabled LightGBM Installation Script
Installs LightGBM with GPU support for RTX 3050
"""

import subprocess
import sys

def run_command(cmd, description):
    """Run a command and display progress"""
    print(f"\n{'='*60}")
    print(f"[*] {description}")
    print(f"{'='*60}")
    print(f"Command: {cmd}")
    print()
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    
    if result.returncode == 0:
        print(f"✓ {description} - SUCCESS")
    else:
        print(f"✗ {description} - FAILED")
        return False
    
    return True

def main():
    print("="*60)
    print("GPU-Enabled LightGBM Installation")
    print("For RTX 3050 6GB")
    print("="*60)
    
    # Step 1: Uninstall existing LightGBM
    print("\n[Step 1/3] Uninstalling existing LightGBM...")
    run_command("pip uninstall lightgbm -y", "Uninstalling LightGBM")
    
    # Step 2: Install GPU-enabled LightGBM
    print("\n[Step 2/3] Installing GPU-enabled LightGBM...")
    print("[!] This may take a few minutes...")
    
    # Try the config-settings method (newer pip)
    success = run_command(
        "pip install lightgbm --config-settings=cmake.define.USE_GPU=ON",
        "Installing LightGBM with GPU support"
    )
    
    if not success:
        print("\n[!] First method failed, trying alternative installation...")
        # Fallback: try installing pre-built wheel or from source
        run_command(
            "pip install lightgbm",
            "Installing standard LightGBM (fallback)"
        )
        print("\n[!] Note: Standard LightGBM installed. GPU may not be available.")
        print("[!] You may need to build from source for GPU support.")
    
    # Step 3: Verify installation
    print("\n[Step 3/3] Verifying installation...")
    verify_code = """
import lightgbm as lgb
print(f'LightGBM version: {lgb.__version__}')

# Try GPU test
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

try:
    gbm = lgb.train(params, train_data, num_boost_round=5, verbose_eval=False)
    print('✓ GPU training successful!')
except Exception as e:
    print(f'✗ GPU training failed: {e}')
"""
    
    result = subprocess.run(
        [sys.executable, "-c", verify_code],
        capture_output=True,
        text=True
    )
    
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    
    print("\n" + "="*60)
    print("Installation Complete!")
    print("="*60)
    print("\nNext steps:")
    print("1. Run: python src/gpu_check.py")
    print("2. If GPU works, train your model: python src/model_training.py")
    print("3. Monitor GPU usage: nvidia-smi -l 1")

if __name__ == "__main__":
    main()
