"""
Shared feature engineering for the severity classifier.

Both train_classifier.py (training) and classifier.py (live inference in the
backend) must turn a raw alert into the exact same feature shape, or the
model's predictions become meaningless. This module is the single source of
truth for that transformation — import it from both places rather than
duplicating the logic.

Feature columns produced:
    - description : str   (free text, fed to a TF-IDF vectorizer)
    - source       : str   (categorical, one-hot encoded)
    - has_ip       : int   (1 if the alert carries an IP, else 0)
    - has_hash     : int   (1 if the alert carries a file/hash value, else 0)
"""

import pandas as pd

FEATURE_COLUMNS = ["description", "source", "has_ip", "has_hash"]


def build_feature_frame(records):
    """
    records: list of dicts, each with at least 'source' and 'description',
             and optionally 'ip' and 'hash'.
    Returns: pandas.DataFrame with the FEATURE_COLUMNS, ready to feed into
             the trained pipeline's .predict()/.fit().
    """
    rows = []
    for r in records:
        rows.append(
            {
                "description": r.get("description") or "",
                "source": r.get("source") or "unknown",
                "has_ip": 1 if r.get("ip") else 0,
                "has_hash": 1 if r.get("hash") else 0,
            }
        )
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)
