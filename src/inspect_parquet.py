import pandas as pd
import os

try:
    df = pd.read_parquet(r"c:\Users\azanm\OneDrive\Desktop\InfoSec_Project\data\train.parquet")
    print("Shape:", df.shape)
    print("Columns:", list(df.columns)[:20])
    print("Dtypes:", df.dtypes[:5])
    print("First row samples:", df.iloc[0, :10].values)
    
    # Check for 'label' or 'class'
    if 'label' in df.columns:
        print("Label column found: 'label'")
    elif 'class' in df.columns:
        print("Label column found: 'class'")
    else:
        print("POSSIBLE LABELS:", [c for c in df.columns if 'lab' in c.lower() or 'target' in c.lower()])

except Exception as e:
    print(e)
