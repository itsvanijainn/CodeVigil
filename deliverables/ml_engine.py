"""
CodeVigil — Week 3 Deliverable: ML Engine Demo
=================================================
Demonstrates the complete ML pipeline:
1. TF-IDF search with cosine similarity
2. Vulnerability type classification (MultinomialNB)
3. Severity prediction (MultinomialNB)
4. Fix/remediation recommendation

Run: python deliverables/ml_engine.py
"""

import json
import sys
sys.path.insert(0, ".")

from ir_engine.tfidf_retriever import TFIDFRetriever
from ir_engine.bm25_retriever import BM25Retriever
from ml_engine.classifier import VulnTypeClassifier
from ml_engine.severity_predictor import SeverityPredictor
from ml_engine.fix_recommender import FixRecommender
from utils.metrics import precision_at_k, recall_at_k, f1_at_k, mean_reciprocal_rank


def main():
    print("\n" + "=" * 70)
    print("  CODEVIGIL — ML ENGINE DEMONSTRATION (Week 3 Deliverable)")
    print("=" * 70)

    # ─────────────────────────────────────────
    # STEP 1: Load Data
    # ─────────────────────────────────────────
    print("\n📦 STEP 1: Loading CVE Database...")
    with open("data/cve_database.json", "r") as f:
        cves = json.load(f)
    print(f"   ✅ Loaded {len(cves)} CVE entries")

    # ─────────────────────────────────────────
    # STEP 2: Initialize Engines
    # ─────────────────────────────────────────
    print("\n🔧 STEP 2: Initializing IR + ML Engines...")

    tfidf_retriever = TFIDFRetriever(cves)
    print(f"   ✅ TF-IDF Retriever ready ({len(tfidf_retriever.get_vocabulary())} features)")

    bm25_retriever = BM25Retriever(cves)
    print(f"   ✅ BM25 Retriever ready")

    type_classifier = VulnTypeClassifier()
    type_metrics = type_classifier.train(cves)
    print(f"   ✅ Type Classifier trained (Accuracy: {type_metrics['accuracy']}, CV: {type_metrics['cv_accuracy_mean']}±{type_metrics['cv_accuracy_std']})")

    severity_predictor = SeverityPredictor()
    sev_metrics = severity_predictor.train(cves)
    print(f"   ✅ Severity Predictor trained (Accuracy: {sev_metrics['accuracy']}, CV: {sev_metrics['cv_accuracy_mean']}±{sev_metrics['cv_accuracy_std']})")

    fix_recommender = FixRecommender(cves)
    print(f"   ✅ Fix Recommender ready")

    # ─────────────────────────────────────────
    # STEP 3: Demo Queries
    # ─────────────────────────────────────────
    print("\n" + "─" * 70)
    print("🔎 STEP 3: Query Processing Demo")
    print("─" * 70)

    queries = [
        "log4j JNDI injection remote code execution",
        "path traversal file read vulnerability",
        "deserialization arbitrary code execution java",
        "buffer overflow privilege escalation linux",
        "authentication bypass unprivileged access",
    ]

    for i, query in enumerate(queries, 1):
        print(f"\n{'─' * 60}")
        print(f"  QUERY {i}: \"{query}\"")
        print(f"{'─' * 60}")

        # TF-IDF Results
        tfidf_results = tfidf_retriever.search(query, top_k=3)
        print(f"\n  📊 TF-IDF Results (Top 3):")
        for j, r in enumerate(tfidf_results, 1):
            print(f"    {j}. [{r['relevance_score']:.4f}] {r['cve_id']} — {r['type']} ({r['severity']})")

        # BM25 Results
        bm25_results = bm25_retriever.search(query, top_k=3)
        print(f"\n  📊 BM25 Results (Top 3):")
        for j, r in enumerate(bm25_results, 1):
            print(f"    {j}. [{r['bm25_score']:.4f}] {r['cve_id']} — {r['type']} ({r['severity']})")

        # ML Classification
        pred_type, type_conf = type_classifier.predict(query)
        pred_sev, sev_conf = severity_predictor.predict(query)
        print(f"\n  🤖 ML Classification:")
        print(f"    Predicted Type:     {pred_type} (confidence: {type_conf:.4f})")
        print(f"    Predicted Severity: {pred_sev} (confidence: {sev_conf:.4f})")

        # Fix Recommendation
        if tfidf_results:
            fix = fix_recommender.get_fix(cve_id=tfidf_results[0]["cve_id"])
            print(f"\n  🔧 Recommended Fix for {tfidf_results[0]['cve_id']}:")
            if fix["specific_fix"]:
                print(f"    {fix['specific_fix']}")
            print(f"    Priority: {fix['priority']}")

    # ─────────────────────────────────────────
    # STEP 4: Evaluation Metrics
    # ─────────────────────────────────────────
    print("\n" + "─" * 70)
    print("📈 STEP 4: Retrieval Evaluation Metrics")
    print("─" * 70)

    # Define ground-truth relevance judgments
    relevance_judgments = {
        "log4j JNDI injection remote code execution": ["CVE-2021-44228"],
        "path traversal file read": ["CVE-2021-41773", "CVE-2021-42013", "CVE-2019-19781", "CVE-2019-11510", "CVE-2018-13379"],
        "deserialization arbitrary code execution": ["CVE-2019-18935", "CVE-2016-4437", "CVE-2022-47966", "CVE-2023-0669"],
        "buffer overflow privilege escalation": ["CVE-2021-3156", "CVE-2015-0235", "CVE-2023-27997", "CVE-2016-0728"],
        "authentication bypass": ["CVE-2020-1472", "CVE-2023-23397", "CVE-2022-1388", "CVE-2020-14882"],
    }

    queries_results_tfidf = []
    queries_results_bm25 = []

    print(f"\n  {'Query':<45} {'TF-IDF P@3':<12} {'BM25 P@3':<12}")
    print(f"  {'─' * 45} {'─' * 12} {'─' * 12}")

    for query, relevant in relevance_judgments.items():
        tfidf_res = tfidf_retriever.search(query, top_k=5)
        bm25_res = bm25_retriever.search(query, top_k=5)

        tfidf_ids = [r["cve_id"] for r in tfidf_res]
        bm25_ids = [r["cve_id"] for r in bm25_res]

        p_tfidf = precision_at_k(tfidf_ids, relevant, 3)
        p_bm25 = precision_at_k(bm25_ids, relevant, 3)

        queries_results_tfidf.append((tfidf_ids, relevant))
        queries_results_bm25.append((bm25_ids, relevant))

        short_query = query[:42] + "..." if len(query) > 42 else query
        print(f"  {short_query:<45} {p_tfidf:<12.4f} {p_bm25:<12.4f}")

    mrr_tfidf = mean_reciprocal_rank(queries_results_tfidf)
    mrr_bm25 = mean_reciprocal_rank(queries_results_bm25)

    print(f"\n  Mean Reciprocal Rank (MRR):")
    print(f"    TF-IDF: {mrr_tfidf:.4f}")
    print(f"    BM25:   {mrr_bm25:.4f}")

    # ─────────────────────────────────────────
    # STEP 5: Classifier Evaluation
    # ─────────────────────────────────────────
    print("\n" + "─" * 70)
    print("📊 STEP 5: ML Classifier Evaluation")
    print("─" * 70)

    print(f"\n  Vulnerability Type Classifier:")
    print(f"    Training Accuracy : {type_metrics['accuracy']}")
    print(f"    5-Fold CV Accuracy: {type_metrics['cv_accuracy_mean']} ± {type_metrics['cv_accuracy_std']}")
    print(f"    Classes: {type_metrics['classes']}")

    print(f"\n  Severity Predictor:")
    print(f"    Training Accuracy : {sev_metrics['accuracy']}")
    print(f"    5-Fold CV Accuracy: {sev_metrics['cv_accuracy_mean']} ± {sev_metrics['cv_accuracy_std']}")
    print(f"    Classes: {sev_metrics['classes']}")

    print("\n" + "=" * 70)
    print("  ✅ ML ENGINE DEMO COMPLETE")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
