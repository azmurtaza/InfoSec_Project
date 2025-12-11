
import pandas as pd
df = pd.read_csv('data/dataset.csv')
print("fileinfo dtype:", df['fileinfo'].dtype)
print("fileinfo head:", df['fileinfo'].head().tolist())
print("packer head:", df['packer'].head().tolist())
