
import os
import json
import pandas as pd
# Use the new extractor (which detects PE or Raw)
from feature_extraction import extract_features 

INPUT_FOLDER = "data/raw_files"
OUTPUT_CSV = "data/new_dataset.csv" 

def build_dataset():
    rows = []
    labels = []

    if not os.path.exists(INPUT_FOLDER):
        print(f"Input folder {INPUT_FOLDER} does not exist.")
        return

    print(f"Scanning {INPUT_FOLDER}...")

    for file_name in os.listdir(INPUT_FOLDER):
        file_path = os.path.join(INPUT_FOLDER, file_name)
        
        # Skip directories
        if os.path.isdir(file_path):
            continue

        # We now process ALL files, not just .exe, to handle "less bits" / fragments
        print(f"Extracting features from: {file_name}")

        features = extract_features(file_path)
        if features is None:
            print(f"Skipping {file_name} (extraction failed)")
            continue

        rows.append(features)

        # Simple labeling based on filename keywords for this demo
        # The user provided files like 'malware1.exe', 'virus1.exe' vs 'vlc', 'winrar'
        fw = file_name.lower()
        if "malware" in fw or "virus" in fw or "test" in fw:
            labels.append(1)
        else:
            labels.append(0)

    if not rows:
        print("No features extracted. Check raw_files directory.")
        return

    df = pd.DataFrame(rows)
    df["class"] = labels # Use 'class' to match model_training convention (dataset.csv uses 'class', usually)
    
    # Ensure specific columns match what model_training expects if we want to merge? 
    # For now, just save what we have.
    df.to_csv(OUTPUT_CSV, index=False)

    print(f"\nDataset saved → {OUTPUT_CSV}")
    print(f"Total samples: {len(df)}")
    print(f"Columns: {len(df.columns)}")

if __name__ == "__main__":
    build_dataset()