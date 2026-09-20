"""
Trains the AI-SOAR severity classifier.

Reads dataset/alerts_dataset.csv (generate it first with
dataset/generate_dataset.py if it doesn't exist yet), trains a
RandomForest pipeline that predicts alert severity (Low/Medium/High/
Critical) from the alert's description, source, and whether it carries
an IP/hash, and saves the fitted pipeline to ai-model/severity_model.joblib.

Run:
    python3 ai-model/train_classifier.py
"""

import os
import sys

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

# Make `from features import build_feature_frame` work whether this script
# is run from the repo root or from inside ai-model/.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_COLUMNS, build_feature_frame  # noqa: E402

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(BASE_DIR)
DATASET_PATH = os.path.join(REPO_ROOT, "dataset", "alerts_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "severity_model.joblib")

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]


def load_dataset():
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found at {DATASET_PATH}. Run dataset/generate_dataset.py first."
        )
    df = pd.read_csv(DATASET_PATH)
    df["ip"] = df["ip"].where(df["ip"].notna(), None)
    df["hash"] = df["hash"].where(df["hash"].notna(), None)
    return df


def build_pipeline():
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "description_tfidf",
                TfidfVectorizer(max_features=400, ngram_range=(1, 2), stop_words="english"),
                "description",
            ),
            ("source_ohe", OneHotEncoder(handle_unknown="ignore"), ["source"]),
        ],
        remainder="passthrough",  # keeps has_ip, has_hash as numeric features
    )

    classifier = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    return Pipeline(steps=[("preprocess", preprocessor), ("classifier", classifier)])


def main():
    df = load_dataset()
    records = df.to_dict(orient="records")
    X = build_feature_frame(records)
    y = df["severity"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)

    print("=== Classification report (held-out test set) ===")
    print(classification_report(y_test, y_pred, labels=SEVERITY_ORDER))
    print("=== Confusion matrix (rows=actual, cols=predicted), order:", SEVERITY_ORDER, "===")
    print(confusion_matrix(y_test, y_pred, labels=SEVERITY_ORDER))

    joblib.dump(pipeline, MODEL_PATH)
    print(f"\nSaved trained model to {MODEL_PATH}")


if __name__ == "__main__":
    main()
