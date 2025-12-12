from __future__ import annotations

import os
import pickle
from typing import Dict

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder


class BugClassifier:
    MODEL_VERSION = 2

    def __init__(self):
        self.encoder = SentenceTransformer("all-MiniLM-L6-v2")

        self.type_classifier = None
        self.component_classifier = None
        self.severity_classifier = None

        self.type_encoder = LabelEncoder()
        self.component_encoder = LabelEncoder()
        self.severity_encoder = LabelEncoder()

        self._load_or_train_models()
        if (
            self.type_classifier is None
            or self.component_classifier is None
            or self.severity_classifier is None
        ):
            self._train_on_sample_data()

    def _load_or_train_models(self) -> None:
        try:
            with open("models/bug_classifier.pkl", "rb") as f:
                models = pickle.load(f)

            if not isinstance(models, dict):
                raise ValueError("Invalid model file format")
            if models.get("version") != self.MODEL_VERSION:
                raise ValueError("Model version mismatch")

            self.type_classifier = models["type"]
            self.component_classifier = models["component"]
            self.severity_classifier = models["severity"]
            self.type_encoder = models["type_encoder"]
            self.component_encoder = models["component_encoder"]
            self.severity_encoder = models["severity_encoder"]
        except (FileNotFoundError, KeyError, ValueError, pickle.UnpicklingError):
            self._train_on_sample_data()

    def _train_on_sample_data(self) -> None:
        samples = [
            (
                "Dashboard shows $0 revenue",
                "Revenue dashboard displaying zero values",
                "bug",
                "analytics_dashboard",
                "critical",
            ),
            (
                "API returns empty response",
                "User API returning null for profile",
                "bug",
                "user_api",
                "high",
            ),
            (
                "App crashes on login",
                "Mobile app crash when user tries to login",
                "bug",
                "mobile_app",
                "critical",
            ),
            (
                "Add dark mode",
                "Please add dark mode support to the dashboard UI",
                "feature",
                "analytics_dashboard",
                "low",
            ),
            (
                "Slow page load",
                "Dashboard takes 10 seconds to load",
                "bug",
                "analytics_dashboard",
                "medium",
            ),
            (
                "Database connection timeout",
                "Getting connection timeouts to primary DB",
                "bug",
                "infrastructure",
                "critical",
            ),
            (
                "Recommendation engine wrong results",
                "ML model predicting incorrect items",
                "bug",
                "recommendation_model",
                "high",
            ),
            (
                "How to reset password",
                "Can't find password reset option",
                "question",
                "user_api",
                "low",
            ),
        ]

        texts = [f"{s[0]} {s[1]}" for s in samples]
        embeddings = self.encoder.encode(texts)

        types = [s[2] for s in samples]
        components = [s[3] for s in samples]
        severities = [s[4] for s in samples]

        self.type_encoder.fit(types)
        self.component_encoder.fit(components)
        self.severity_encoder.fit(severities)

        self.type_classifier = RandomForestClassifier(
            n_estimators=100, random_state=42
        )
        self.type_classifier.fit(embeddings, self.type_encoder.transform(types))

        self.component_classifier = RandomForestClassifier(
            n_estimators=100, random_state=42
        )
        self.component_classifier.fit(
            embeddings, self.component_encoder.transform(components)
        )

        self.severity_classifier = RandomForestClassifier(
            n_estimators=100, random_state=42
        )
        self.severity_classifier.fit(
            embeddings, self.severity_encoder.transform(severities)
        )

        self._save_models()

    def _save_models(self) -> None:
        os.makedirs("models", exist_ok=True)
        with open("models/bug_classifier.pkl", "wb") as f:
            pickle.dump(
                {
                    "version": self.MODEL_VERSION,
                    "type": self.type_classifier,
                    "component": self.component_classifier,
                    "severity": self.severity_classifier,
                    "type_encoder": self.type_encoder,
                    "component_encoder": self.component_encoder,
                    "severity_encoder": self.severity_encoder,
                },
                f,
            )

    def classify(self, title: str, description: str) -> Dict:
        if (
            self.type_classifier is None
            or self.component_classifier is None
            or self.severity_classifier is None
        ):
            self._train_on_sample_data()

        text = f"{title} {description}"
        embedding = self.encoder.encode([text])

        type_probs = self.type_classifier.predict_proba(embedding)[0]
        type_pred = self.type_encoder.inverse_transform([np.argmax(type_probs)])[0]

        component_probs = self.component_classifier.predict_proba(embedding)[0]
        component_pred = self.component_encoder.inverse_transform(
            [np.argmax(component_probs)]
        )[0]

        severity_probs = self.severity_classifier.predict_proba(embedding)[0]
        severity_pred = self.severity_encoder.inverse_transform(
            [np.argmax(severity_probs)]
        )[0]

        confidence = (
            max(type_probs) + max(component_probs) + max(severity_probs)
        ) / 3

        return {
            "type": type_pred,
            "type_confidence": float(max(type_probs)),
            "component": component_pred,
            "component_confidence": float(max(component_probs)),
            "severity": severity_pred,
            "severity_confidence": float(max(severity_probs)),
            "overall_confidence": float(confidence),
        }
