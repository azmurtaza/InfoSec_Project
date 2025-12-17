
import lightgbm as lgb
import numpy as np
import sys

print(f"LightGBM Version: {lgb.__version__}")

try:
    data = np.random.rand(50, 2)
    label = np.random.randint(2, size=50)
    train_data = lgb.Dataset(data, label=label)
    params = {'device': 'gpu', 'verbosity': -1, 'gpu_platform_id': 0, 'gpu_device_id': 0}
    bst = lgb.train(params, train_data, num_boost_round=1)
    print("GPU support: AVAILABLE")
except Exception as e:
    print(f"GPU support: NOT AVAILABLE ({e})")
