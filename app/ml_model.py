# -*- coding: utf-8 -*-
"""
Modèle ML léger (régression logistique) pour classifier une URL
phishing vs légitime à partir de features lexicales simples.
Pas de GPU, pas de dépendance lourde — entraînement en quelques secondes.
"""
import os
import re
import joblib
import numpy as np
import tldextract
from brand_list import closest_brand

# Offline-only extractor — see url_analysis.py for rationale.
_extract = tldextract.TLDExtract(suffix_list_urls=())

MODEL_PATH = os.path.join(os.path.dirname(__file__), "data", "phishing_model.joblib")

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click"}
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

FEATURE_NAMES = [
    "length", "num_dots", "num_hyphens", "num_digits",
    "has_at", "has_ip", "suspicious_tld", "has_https", "num_subdomains",
    "brand_edit_distance", "is_near_brand_typo",
]


def extract_features(url: str) -> np.ndarray:
    ext = _extract(url)
    host = ".".join(p for p in [ext.subdomain, ext.domain, ext.suffix] if p)

    # Typosquatting signal: edit distance between the domain and the
    # closest known brand. Capped at 5 so a totally unrelated domain
    # (distance 15+) doesn't dominate the feature scale.
    _, dist = closest_brand(ext.domain.lower())
    capped_dist = min(dist, 5)

    feats = [
        len(url),
        url.count("."),
        url.count("-"),
        sum(c.isdigit() for c in url),
        1 if "@" in url else 0,
        1 if IP_RE.match(ext.domain) else 0,
        1 if ext.suffix.lower() in SUSPICIOUS_TLDS else 0,
        1 if url.lower().startswith("https://") else 0,
        ext.subdomain.count(".") + (1 if ext.subdomain else 0),
        capped_dist,
        1 if dist <= 2 else 0,
    ]
    return np.array(feats, dtype=float)


def train(csv_path="data/url_dataset.csv", model_path=MODEL_PATH):
    import csv
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score

    urls, labels = [], []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"])
            labels.append(int(row["label"]))

    X = np.array([extract_features(u) for u in urls])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = LogisticRegression(max_iter=1000)
    clf.fit(X_train, y_train)
    acc = accuracy_score(y_test, clf.predict(X_test))
    print(f"Accuracy sur l'ensemble de test (synthétique) : {acc:.3f}")

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(clf, model_path)
    print(f"Modèle sauvegardé : {model_path}")
    return acc


_model_cache = None


def _load_model():
    global _model_cache
    if _model_cache is None and os.path.exists(MODEL_PATH):
        _model_cache = joblib.load(MODEL_PATH)
    return _model_cache


def predict_url(url: str) -> dict:
    model = _load_model()
    if model is None:
        return {"status": "untrained"}
    feats = extract_features(url).reshape(1, -1)
    proba = model.predict_proba(feats)[0][1]  # P(phishing)
    label = "malicious" if proba >= 0.7 else ("suspicious" if proba >= 0.4 else "legit")
    return {"status": "ok", "phishing_probability": round(float(proba), 3), "verdict": label}


if __name__ == "__main__":
    import generate_dataset
    if not os.path.exists("data/url_dataset.csv"):
        generate_dataset.generate()
    train()
