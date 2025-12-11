
import pandas as pd
import numpy as np

try:
    df = pd.read_csv('data/dataset.csv')
    print(f"Total rows: {len(df)}")
    
    if 'class' in df.columns:
        print("Class counts:")
        print(df['class'].value_counts())
    else:
        print("'class' column not found!")
    
    # Check non-numeric columns
    numerics = ['int16', 'int32', 'int64', 'float16', 'float32', 'float64']
    newdf = df.select_dtypes(exclude=numerics)
    print("\nNon-numeric columns:")
    print(newdf.columns.tolist())
    
    # Check first few rows of 'class'
    print("\nFirst 5 classes:", df['class'].head().tolist())
    print("Last 5 classes:", df['class'].tail().tolist())

except Exception as e:
    print(f"Error: {e}")
