import os
import json
import pandas as pd
from feature_extraction import extract_pe_features

INPUT_FOLDER = "data/raw_files"
OUTPUT_CSV = "data/dataset.csv"

def build_dataset():
    rows = []
    labels = []

    for file_name in os.listdir(INPUT_FOLDER):
        file_path = os.path.join(INPUT_FOLDER, file_name)

        if not file_name.lower().endswith(".exe"):
            continue

        print(f"Extracting: {file_name}")

        features = extract_pe_features(file_path)
        if features is None:
            continue

        rows.append(features)

        # Label by folder name (benign/malicious)
        if "malware" in file_name.lower():
            labels.append(1)
        else:
            labels.append(0)

    df = pd.DataFrame(rows)
    df["label"] = labels
    df.to_csv(OUTPUT_CSV, index=False)

    print(f"\nDataset saved → {OUTPUT_CSV}")
    print(f"Total samples: {len(df)}")

if __name__ == "__main__":
    build_dataset()