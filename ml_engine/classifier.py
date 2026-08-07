"""
CodeVigil — Vulnerability Type Classifier
============================================
Uses TF-IDF + Multinomial Naive Bayes to classify
vulnerability type from text description.
"""

import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import cross_val_score, KFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import numpy as np


class VulnTypeClassifier:
    """
    Multinomial Naive Bayes classifier for vulnerability type classification.
    
    Trains on CVE descriptions to predict vulnerability categories:
    - Remote Code Execution
    - SQL Injection
    - Path Traversal
    - Buffer Overflow
    - Deserialization
    - Authentication Bypass
    - Privilege Escalation
    - Command Injection
    - etc.
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
        Train the classifier on CVE data.
        
        Args:
            cve_entries: List of CVE dicts with 'description' and 'type' fields
            
        Returns:
            Training metrics dict
        """
        texts = []
        labels = []

        for entry in cve_entries:
            text = f"{entry['description']} {entry.get('affected_software', '')}"
            texts.append(text)
            labels.append(entry["type"])

        # Transform text to TF-IDF vectors
        X = self.vectorizer.fit_transform(texts)
        y = np.array(labels)

        # Train classifier
        self.classifier.fit(X, y)
        self.classes_ = self.classifier.classes_

        # Cross-validation
        kf = KFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(self.classifier, X, y, cv=kf, scoring="accuracy")

        # Train predictions for report
        y_pred = self.classifier.predict(X)

        metrics = {
            "accuracy": round(accuracy_score(y, y_pred), 4),
            "cv_accuracy_mean": round(float(np.mean(cv_scores)), 4),
            "cv_accuracy_std": round(float(np.std(cv_scores)), 4),
            "cv_scores": [round(float(s), 4) for s in cv_scores],
            "classification_report": classification_report(y, y_pred, output_dict=True, zero_division=0),
            "num_classes": len(self.classes_),
            "num_samples": len(texts),
            "classes": list(self.classes_),
        }

        return metrics

    def predict(self, text: str) -> tuple[str, float]:
        """
        Predict vulnerability type for a given text.
        
        Returns:
            (predicted_type, confidence_score)
        """
        X = self.vectorizer.transform([text])
        predicted_type = self.classifier.predict(X)[0]
        probabilities = self.classifier.predict_proba(X)[0]
        confidence = float(max(probabilities))

        return predicted_type, round(confidence, 4)

    def predict_proba(self, text: str) -> list[tuple[str, float]]:
        """
        Return all class probabilities for a given text.
        
        Returns:
            List of (class_name, probability) tuples sorted by probability
        """
        X = self.vectorizer.transform([text])
        probabilities = self.classifier.predict_proba(X)[0]

        results = list(zip(self.classes_, probabilities))
        results.sort(key=lambda x: x[1], reverse=True)

        return [(cls, round(float(prob), 4)) for cls, prob in results]

    def print_evaluation(self, cve_entries: list[dict]):
        """Print full evaluation metrics."""
        texts = [f"{e['description']} {e.get('affected_software', '')}" for e in cve_entries]
        y_true = [e["type"] for e in cve_entries]

        X = self.vectorizer.transform(texts)
        y_pred = self.classifier.predict(X)

        print("=" * 60)
        print("  VULNERABILITY TYPE CLASSIFIER — EVALUATION")
        print("=" * 60)
        print(f"\n  Training Accuracy : {accuracy_score(y_true, y_pred):.4f}")
        print(f"\n  Classification Report:")
        print(classification_report(y_true, y_pred))
        print(f"\n  Confusion Matrix:")
        print(confusion_matrix(y_true, y_pred, labels=list(self.classes_)))
        print("=" * 60)


# ─────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    with open("data/cve_database.json", "r") as f:
        cves = json.load(f)

    classifier = VulnTypeClassifier()
    metrics = classifier.train(cves)

    print(f"✅ Classifier trained on {metrics['num_samples']} CVEs")
    print(f"   Classes: {metrics['classes']}")
    print(f"   Training Accuracy: {metrics['accuracy']}")
    print(f"   CV Accuracy: {metrics['cv_accuracy_mean']} ± {metrics['cv_accuracy_std']}")
    print()

    # Test predictions
    test_inputs = [
        "A SQL injection vulnerability allows attackers to execute arbitrary SQL queries",
        "Buffer overflow in the parsing function allows heap corruption and code execution",
        "Path traversal vulnerability allows reading arbitrary files from the server",
        "Deserialization of untrusted data leads to remote code execution",
        "Authentication bypass allows unauthenticated access to admin panel",
    ]

    print("🔎 PREDICTION DEMO:")
    print("-" * 60)
    for text in test_inputs:
        pred_type, confidence = classifier.predict(text)
        print(f"\n  Input: \"{text[:60]}...\"")
        print(f"  Predicted Type: {pred_type}")
        print(f"  Confidence: {confidence:.4f}")
