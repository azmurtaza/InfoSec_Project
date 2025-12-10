import pandas as pd
import json
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

DATASET_CSV = "../data/dataset.csv"
MODEL_PATH = "../models/classifier.pkl"
FEATURES_PATH = "../models/features.json"

def train_model():
    df = pd.read_csv(DATASET_CSV)

    X = df.drop("label", axis=1)
    y = df["label"]

    # Save feature names
    with open(FEATURES_PATH, "w") as f:
        json.dump(list(X.columns), f)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42
    )

    model = RandomForestClassifier(n_estimators=200)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)

    print(f"Accuracy: {acc*100:.2f}%")

    joblib.dump(model, MODEL_PATH)
    print(f"Model saved → {MODEL_PATH}")

if __name__ == "__main__":
    train_model()
