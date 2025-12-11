import pandas as pd
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
dataset_path = os.path.join(script_dir, '..', 'data', 'dataset.csv')

df = pd.read_csv(dataset_path)
print("--- DATASET DIAGNOSTICS ---")
print(f"Total Rows: {len(df)}")
print(f"Columns found: {list(df.columns)}")
if 'class' in df.columns:
    print(f"Class Distribution:\n{df['class'].value_counts()}")
else:
    print("[!] 'class' column NOT found. Check the column names above.")