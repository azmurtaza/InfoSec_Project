
import pandas as pd
df = pd.read_csv('data/dataset.csv')
numerics = ['int16', 'int32', 'int64', 'float16', 'float32', 'float64', 'int', 'float']
non_num = df.select_dtypes(exclude=numerics).columns.tolist()
print("Non-numeric columns:", non_num)
for col in non_num:
    print(f"{col}: {df[col].nunique()} unique values")
