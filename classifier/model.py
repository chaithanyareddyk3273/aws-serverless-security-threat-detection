"""
Threat classifier wrapper — loaded by the Lambda function.
Handles model loading, prediction, and confidence scoring.
"""
import os
import pickle
import numpy as np

_BASE = os.path.join(os.path.dirname(__file__), "model_artifacts")


class ThreatClassifier:
    _instance = None

    def __new__(cls):
        """Singleton — model loads once per Lambda container warm start."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load()
        return cls._instance

    def _load(self):
        print("[Model] Loading model artifacts...")
        with open(f"{_BASE}/model.pkl",   "rb") as f: self.model   = pickle.load(f)
        with open(f"{_BASE}/scaler.pkl",  "rb") as f: self.scaler  = pickle.load(f)
        with open(f"{_BASE}/encoder.pkl", "rb") as f: self.encoder = pickle.load(f)
        print(f"[Model] Ready. Classes: {list(self.encoder.classes_)}")

    def predict(self, feature_vector: np.ndarray) -> dict:
        """
        Classify a single feature vector.

        Args:
            feature_vector: np.ndarray of shape (1, N)

        Returns:
            {
                "threat":      "brute_force",
                "severity":    "High",
                "confidence":  0.87,
                "probabilities": {"normal": 0.05, "brute_force": 0.87, ...}
            }
        """
        from classifier.threat_types import get_severity

        X = self.scaler.transform(feature_vector)
        proba = self.model.predict_proba(X)[0]

        # Map class indices → threat labels
        class_probs = {
            label: float(round(p, 4))
            for label, p in zip(self.encoder.classes_, proba)
        }

        predicted_idx  = int(np.argmax(proba))
        threat_label   = self.encoder.classes_[predicted_idx]
        confidence     = float(round(proba[predicted_idx], 4))
        severity       = get_severity(threat_label)

        return {
            "threat":        threat_label,
            "severity":      severity,
            "confidence":    confidence,
            "probabilities": class_probs,
        }
