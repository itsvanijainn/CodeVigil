"""
CodeVigil — Severity Predictor
=================================
Uses TF-IDF + Multinomial Naive Bayes to predict
vulnerability severity level from text description.
"""

import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import cross_val_score, KFold
from sklearn.metrics import classification_report, accuracy_score
import numpy as np


class SeverityPredictor:
    """
    Multinomial Naive Bayes classifier for severity prediction.
    
    Predicts severity level: Low, Medium, High, Critical
    """

    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words="english",
            ngram_range=(1, 2),
            sublinear_tf=True,
        )
        self.classifier = MultinomialNB(alpha=1.0)
        self.classes_ = None

    def train(self, cve_entries: list[dict]) -> dict:
        """
        Train the severity predictor.
        
        Args:
            cve_entries: List of CVE dicts with 'description' and 'severity' fields
            
        Returns:
            Training metrics dict
        """
        texts = []
        labels = []

        for entry in cve_entries:
            text = f"{entry['description']} {entry['type']} {entry.get('affected_software', '')}"
            texts.append(text)
            labels.append(entry["severity"])

        X = self.vectorizer.fit_transform(texts)
        y = np.array(labels)

        self.classifier.fit(X, y)
        self.classes_ = self.classifier.classes_

        # Cross-validation
        kf = KFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(self.classifier, X, y, cv=kf, scoring="accuracy")

        y_pred = self.classifier.predict(X)

        metrics = {
            "accuracy": round(accuracy_score(y, y_pred), 4),
            "cv_accuracy_mean": round(float(np.mean(cv_scores)), 4),
            "cv_accuracy_std": round(float(np.std(cv_scores)), 4),
            "cv_scores": [round(float(s), 4) for s in cv_scores],
            "classification_report": classification_report(y, y_pred, output_dict=True, zero_division=0),
            "num_samples": len(texts),
            "classes": list(self.classes_),
        }

        return metrics

    def predict(self, text: str) -> tuple[str, float]:
        """
        Predict severity level for a given text.
        
        Returns:
            (predicted_severity, confidence_score)
        """
        X = self.vectorizer.transform([text])
        predicted_severity = self.classifier.predict(X)[0]
        probabilities = self.classifier.predict_proba(X)[0]
        confidence = float(max(probabilities))

        return predicted_severity, round(confidence, 4)

    def predict_proba(self, text: str) -> list[tuple[str, float]]:
        """
        Return all severity probabilities.
        
        Returns:
            List of (severity, probability) tuples sorted by probability
        """
        X = self.vectorizer.transform([text])
        probabilities = self.classifier.predict_proba(X)[0]

        results = list(zip(self.classes_, probabilities))
        results.sort(key=lambda x: x[1], reverse=True)

        return [(sev, round(float(prob), 4)) for sev, prob in results]


# ─────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    with open("data/cve_database.json", "r") as f:
        cves = json.load(f)

    predictor = SeverityPredictor()
    metrics = predictor.train(cves)

    print(f"✅ Severity predictor trained on {metrics['num_samples']} CVEs")
    print(f"   Classes: {metrics['classes']}")
    print(f"   Training Accuracy: {metrics['accuracy']}")
    print(f"   CV Accuracy: {metrics['cv_accuracy_mean']} ± {metrics['cv_accuracy_std']}")
    print()

    test_inputs = [
        "Remote code execution vulnerability allows complete system compromise",
        "Denial of service through malformed packets",
        "Information disclosure in debug endpoint",
        "Authentication bypass with unprivileged access",
    ]

    print("🔎 SEVERITY PREDICTION DEMO:")
    print("-" * 60)
    for text in test_inputs:
        sev, conf = predictor.predict(text)
        print(f"\n  Input: \"{text}\"")
        print(f"  Predicted Severity: {sev} (confidence: {conf:.4f})")
