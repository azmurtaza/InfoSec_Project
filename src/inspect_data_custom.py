import pandas as pd
import os

def check_data():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Assuming code is running from src or root, adjust paths
    base_dir = r"C:\Users\husna\Downloads\infosec\InfoSec_Project"
    d1 = os.path.join(base_dir, 'data', 'dataset.csv')
    d2 = os.path.join(base_dir, 'data', 'new_dataset.csv')
    
    print(f"--- Checking {d1} ---")
    if os.path.exists(d1):
        df1 = pd.read_csv(d1)
        print(f"Shape: {df1.shape}")
        if 'class' in df1.columns:
            print(f"Class Balance:\n{df1['class'].value_counts()}")
        else:
            print("No 'class' column found.")
            
        # Check for PE features presence
        if 'NumberOfSections' in df1.columns:
            print(f"Has PE features. Non-null sections: {df1['NumberOfSections'].count()}")
    else:
        print("Not found.")

    print(f"\n--- Checking {d2} ---")
    if os.path.exists(d2):
        df2 = pd.read_csv(d2)
        print(f"Shape: {df2.shape}")
        if 'class' in df2.columns:
            print(f"Class Balance:\n{df2['class'].value_counts()}")
        
        # Check for PE features
        if 'NumberOfSections' in df2.columns:
            print(f"Has PE features. Non-null sections: {df2['NumberOfSections'].count()}")
        else:
            print("No PE features found (likely Byte-based).")

if __name__ == "__main__":
    check_data()
