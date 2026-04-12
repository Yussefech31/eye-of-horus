"""
Eye of Horus — ML Threat Classifier
Trains a multi-source threat classification model on labeled data
and exposes a scoring function for use by the Spark processor.

Model pipeline:
    Text → TF-IDF → Logistic Regression  (fast, interpretable)
    Text → TF-IDF → Random Forest        (robust, non-linear)
    Text → CVSS boost                    (structured signal from NVD)

Usage:
    # Train:
    python models/threat_classifier.py --train

    # Predict on sample:
    python models/threat_classifier.py --predict
"""

import sys
import argparse
import pickle
import json
from pathlib import Path
from datetime import datetime

import numpy as np
from loguru import logger
from sklearn.pipeline        import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model    import LogisticRegression
from sklearn.ensemble        import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics         import classification_report, confusion_matrix
from sklearn.preprocessing   import LabelEncoder

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import threat as threat_cfg

MODEL_DIR  = Path(__file__).resolve().parent
MODELS = {
    "logistic":  MODEL_DIR / "logistic_regression.pkl",
    "rf":        MODEL_DIR / "random_forest.pkl",
    "isolation": MODEL_DIR / "isolation_forest.pkl",
    "tfidf":     MODEL_DIR / "tfidf_vectorizer.pkl",
}


# ══════════════════════════════════════════════════════════════════════════════
#  Synthetic Training Data Generator
#  In production: replace with labeled data from MongoDB (threat_scores collection)
# ══════════════════════════════════════════════════════════════════════════════

def generate_synthetic_data() -> tuple[list[str], list[int]]:
    """
    Generate synthetic labeled training examples.
    Labels: 1 = threat, 0 = benign

    In production, load real labeled records from MongoDB using:
        db.threat_scores.find({"label": {"$exists": True}})
    """
    threat_samples = [
        "DDoS attack targeting government websites Anonymous operation",
        "Critical zero-day exploit CVE-2024 ransomware spreading rapidly",
        "Massive data breach exposed 10 million credentials leaked darkweb",
        "Hacktivists plan coordinated cyberattack on banking infrastructure",
        "New malware botnet discovered targeting IoT devices critical",
        "Remote code execution vulnerability CVSS 9.8 actively exploited",
        "Phishing campaign stealing credentials banking users compromised",
        "Ransomware group published stolen data on leak site terabytes",
        "SQL injection vulnerability exposed customer database dump",
        "OpIsrael hacktivist campaign defacing websites DDoS attacks",
        "APT group infiltrated energy sector systems backdoor installed",
        "Critical infrastructure attack power grid vulnerability exploit",
        "Password dump released millions accounts exposed breach credential",
        "Vulnerability actively exploited in the wild patch immediately",
        "Stolen credit card numbers sold dark web marketplace dump",
        "Cyber espionage campaign targeting defense contractors APT28",
        "Malicious npm package supply chain attack thousands infected",
        "Russian threat actors targeting NATO countries critical systems",
        "Killnet DDoS attacks against European financial institutions",
        "Scattered Spider social engineering breached major corporation",
    ]

    benign_samples = [
        "Security researchers published new defensive tool open source",
        "How to configure a firewall best practices guide tutorial",
        "Python programming tutorial for beginners data science",
        "New software update released bug fixes performance improvements",
        "Cybersecurity conference keynote highlights zero trust adoption",
        "Researchers analyzed historical attack patterns academic paper",
        "Introduction to machine learning neural networks guide",
        "Open source project releases new version with enhancements",
        "Cloud computing costs optimization strategies guide",
        "Network monitoring tools comparison enterprise security",
        "Interview tips for cybersecurity professionals career advice",
        "Book review cybersecurity leadership management principles",
        "Weekly roundup technology news AI developments",
        "CTF competition results writeup reverse engineering challenge",
        "Bug bounty program launched responsible disclosure policy",
        "Security certification CISSP study guide exam tips",
        "Podcast episode discussing cyber insurance market trends",
        "Government cybersecurity budget allocation report published",
        "University offers new cybersecurity degree program enrollment",
        "Threat modeling workshop enterprise architecture discussion",
    ]

    texts  = threat_samples + benign_samples
    labels = [1] * len(threat_samples) + [0] * len(benign_samples)
    return texts, labels


# ══════════════════════════════════════════════════════════════════════════════
#  TF-IDF + Logistic Regression Pipeline
# ══════════════════════════════════════════════════════════════════════════════

def build_lr_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=10_000,
            min_df=1,
            sublinear_tf=True,
            stop_words="english",
        )),
        ("clf", LogisticRegression(
            C=1.0,
            max_iter=500,
            class_weight="balanced",
            solver="lbfgs",
            random_state=42,
        )),
    ])


# ══════════════════════════════════════════════════════════════════════════════
#  TF-IDF + Random Forest Pipeline
# ══════════════════════════════════════════════════════════════════════════════

def build_rf_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=5_000,
            min_df=1,
            sublinear_tf=True,
            stop_words="english",
        )),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        )),
    ])


# ══════════════════════════════════════════════════════════════════════════════
#  Isolation Forest — Anomaly Detector
# ══════════════════════════════════════════════════════════════════════════════

def build_isolation_forest(X_tfidf) -> IsolationForest:
    """
    Trains an Isolation Forest on TF-IDF vectors.
    Detects novel / out-of-distribution threat patterns not seen before.
    contamination = expected % of anomalies in the data.
    """
    model = IsolationForest(
        n_estimators=200,
        contamination=0.15,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_tfidf)
    return model


# ══════════════════════════════════════════════════════════════════════════════
#  Train & Evaluate
# ══════════════════════════════════════════════════════════════════════════════

def train(use_mongo: bool = False) -> None:
    """
    Train all models and save them to disk.
    Set use_mongo=True in production to load labels from MongoDB.
    """
    logger.info("🧠 Loading training data...")

    if use_mongo:
        # Production path: load from MongoDB
        from pymongo import MongoClient
        from config.settings import mongo as mongo_cfg
        client = MongoClient(mongo_cfg.URI)
        docs = list(
            client[mongo_cfg.DB_NAME][mongo_cfg.COLLECTION_THREATS]
            .find({"label": {"$exists": True}}, {"text": 1, "label": 1})
        )
        texts  = [d["text"] for d in docs]
        labels = [d["label"] for d in docs]
        client.close()
        logger.info(f"Loaded {len(texts)} labeled records from MongoDB.")
    else:
        texts, labels = generate_synthetic_data()
        logger.warning(
            "Using synthetic training data. "
            "Replace with real labeled data from MongoDB for production."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, random_state=42, stratify=labels
    )

    # ── Train Logistic Regression ─────────────────────────────────────────────
    logger.info("Training Logistic Regression pipeline...")
    lr_pipeline = build_lr_pipeline()
    lr_pipeline.fit(X_train, y_train)
    lr_scores = cross_val_score(lr_pipeline, texts, labels, cv=5, scoring="f1")
    logger.info(f"LR CV F1: {lr_scores.mean():.3f} ± {lr_scores.std():.3f}")
    y_pred_lr = lr_pipeline.predict(X_test)
    print("\n── Logistic Regression ──")
    print(classification_report(y_test, y_pred_lr, target_names=["Benign", "Threat"]))

    # ── Train Random Forest ───────────────────────────────────────────────────
    logger.info("Training Random Forest pipeline...")
    rf_pipeline = build_rf_pipeline()
    rf_pipeline.fit(X_train, y_train)
    rf_scores = cross_val_score(rf_pipeline, texts, labels, cv=5, scoring="f1")
    logger.info(f"RF CV F1: {rf_scores.mean():.3f} ± {rf_scores.std():.3f}")
    y_pred_rf = rf_pipeline.predict(X_test)
    print("\n── Random Forest ──")
    print(classification_report(y_test, y_pred_rf, target_names=["Benign", "Threat"]))

    # ── Train Isolation Forest (on tfidf features) ─────────────────────────
    logger.info("Training Isolation Forest...")
    tfidf_vec = lr_pipeline.named_steps["tfidf"]
    X_tfidf   = tfidf_vec.transform(texts).toarray()
    iso_model = build_isolation_forest(X_tfidf)

    # ── Save models ───────────────────────────────────────────────────────────
    MODEL_DIR.mkdir(exist_ok=True)

    with open(MODELS["logistic"], "wb") as f:
        pickle.dump(lr_pipeline, f)
    with open(MODELS["rf"], "wb") as f:
        pickle.dump(rf_pipeline, f)
    with open(MODELS["isolation"], "wb") as f:
        pickle.dump(iso_model, f)
    with open(MODELS["tfidf"], "wb") as f:
        pickle.dump(tfidf_vec, f)

    # Save metadata
    meta = {
        "trained_at":  datetime.utcnow().isoformat(),
        "n_samples":   len(texts),
        "lr_cv_f1":    float(lr_scores.mean()),
        "rf_cv_f1":    float(rf_scores.mean()),
        "models":      {k: str(v) for k, v in MODELS.items()},
    }
    with open(MODEL_DIR / "metadata.json", "w") as f:
        json.dump(meta, f, indent=2)

    logger.success("✅ All models saved to models/")


# ══════════════════════════════════════════════════════════════════════════════
#  Inference
# ══════════════════════════════════════════════════════════════════════════════

class ThreatClassifier:
    """
    Loads trained models and provides a predict() method
    that returns a [0,1] threat probability for any text.
    """

    def __init__(self) -> None:
        self._lr  = self._load(MODELS["logistic"])
        self._rf  = self._load(MODELS["rf"])
        self._iso = self._load(MODELS["isolation"])
        self._tfidf = self._load(MODELS["tfidf"])

    @staticmethod
    def _load(path: Path):
        if not path.exists():
            raise FileNotFoundError(
                f"Model not found: {path}. Run: python models/threat_classifier.py --train"
            )
        with open(path, "rb") as f:
            return pickle.load(f)

    def predict_proba(self, text: str) -> float:
        """
        Returns the ensemble threat probability in [0, 1].
        Ensemble = average of LR + RF probabilities.
        Anomaly detector adds a bonus if the text is flagged as anomalous.
        """
        # Classification probability
        lr_prob = self._lr.predict_proba([text])[0][1]
        rf_prob = self._rf.predict_proba([text])[0][1]
        ensemble_prob = (lr_prob + rf_prob) / 2

        # Anomaly detection bonus
        x_tfidf = self._tfidf.transform([text]).toarray()
        iso_score = self._iso.decision_function(x_tfidf)[0]
        # iso_score: negative = anomalous. Normalize to [0,1] bonus.
        anomaly_bonus = max(0.0, -iso_score / 0.5) * 0.1

        final = min(ensemble_prob + anomaly_bonus, 1.0)
        return round(final, 4)

    def is_threat(self, text: str, threshold: float | None = None) -> bool:
        threshold = threshold or threat_cfg.THRESHOLD
        return self.predict_proba(text) >= threshold

    def explain(self, text: str) -> dict:
        """Return detailed breakdown for dashboarding."""
        lr_prob = self._lr.predict_proba([text])[0][1]
        rf_prob = self._rf.predict_proba([text])[0][1]
        final   = self.predict_proba(text)
        return {
            "lr_probability":  round(lr_prob, 4),
            "rf_probability":  round(rf_prob, 4),
            "ensemble_score":  final,
            "is_threat":       final >= threat_cfg.THRESHOLD,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  CLI Entry Point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--train",   action="store_true", help="Train and save models")
    parser.add_argument("--predict", action="store_true", help="Run prediction demo")
    parser.add_argument("--mongo",   action="store_true", help="Load training data from MongoDB")
    args = parser.parse_args()

    if args.train:
        train(use_mongo=args.mongo)

    if args.predict:
        logger.info("Loading classifier for inference demo...")
        classifier = ThreatClassifier()

        test_texts = [
            "DDoS attack launched against hospital infrastructure ransomware spreading",
            "Company announced new security awareness training program for employees",
            "Zero-day exploit CVE-2024-9999 actively exploited in the wild CVSS 9.8",
            "Python tutorial: how to build a REST API with FastAPI framework",
        ]

        print("\n── Threat Classification Results ──")
        for text in test_texts:
            result = classifier.explain(text)
            label  = "🚨 THREAT" if result["is_threat"] else "✅  Benign"
            print(f"\nText: {text[:70]}...")
            print(f"  Score: {result['ensemble_score']} | {label}")
            print(f"  LR: {result['lr_probability']} | RF: {result['rf_probability']}")
