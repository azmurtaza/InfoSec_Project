import pandas as pd
import joblib
import numpy as np
import os

# Check dataset distribution
train_path = r"c:\Users\azanm\OneDrive\Desktop\InfoSec_Project\data\train.parquet"
df = pd.read_parquet(train_path)

print("=== Dataset Analysis ===")
print(f"Total samples: {len(df)}")
print(f"\nLabel distribution:")
print(df['Label'].value_counts())
print(f"\nLabel percentages:")
print(df['Label'].value_counts(normalize=True) * 100)

# Check model
model_path = r"c:\Users\azanm\OneDrive\Desktop\InfoSec_Project\models\classifier.pkl"
clf = joblib.load(model_path)

print(f"\n=== Model Info ===")
print(f"Model type: {type(clf)}")
print(f"Classes: {clf.classes_}")

# Test on random benign samples
benign_samples = df[df['Label'] == 0].sample(n=10, random_state=42)
X_benign = benign_samples.drop(columns=['Label'])

print(f"\n=== Testing on 10 Benign Samples ===")
for i, (idx, row) in enumerate(benign_samples.iterrows()):
    X = row.drop('Label').values.reshape(1, -1)
    proba = clf.predict_proba(X)[0]
    pred = clf.predict(X)[0]
    print(f"Sample {i+1}: Pred={pred}, Proba(benign)={proba[1]:.4f}, Proba(malware)={proba[2]:.4f}")
