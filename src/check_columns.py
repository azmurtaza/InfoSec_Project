
import pandas as pd
try:
    df = pd.read_csv('data/dataset.csv', nrows=1)
    with open('cols.txt', 'w') as f:
        for col in df.columns:
            f.write(col + '\n')
    print("Columns written to cols.txt")
except Exception as e:
    print(e)
#temp