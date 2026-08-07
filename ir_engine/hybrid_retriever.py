"""
CodeVigil — Hybrid Retriever
==============================
Combines TF-IDF and BM25 scores using Reciprocal Rank Fusion (RRF).
"""

import json
from ir_engine.tfidf_retriever import TFIDFRetriever
from ir_engine.bm25_retriever import BM25Retriever


class HybridRetriever:
    """
    Hybrid retriever combining TF-IDF + BM25 using Reciprocal Rank Fusion.
    
    RRF formula: score(d) = Σ 1 / (k + rank_i(d))
    where k is a constant (default 60) and rank_i is the rank in retriever i.
    """

    def __init__(self, cve_entries: list[dict], k: int = 60):
        """Initialize both retrievers."""
        self.cve_entries = cve_entries
        self.tfidf = TFIDFRetriever(cve_entries)
        self.bm25 = BM25Retriever(cve_entries)
        self.k = k  # RRF constant

    def search(self, query: str, top_k: int = 5, tfidf_weight: float = 0.5, bm25_weight: float = 0.5) -> list[dict]:
        """
        Search using hybrid TF-IDF + BM25 with Reciprocal Rank Fusion.
        
        Args:
            query: User's search query
            top_k: Number of results to return
            tfidf_weight: Weight for TF-IDF component
            bm25_weight: Weight for BM25 component
            
        Returns:
            List of dicts with CVE info + hybrid score
        """
        # Get results from both retrievers (fetch more for fusion)
        tfidf_results = self.tfidf.search(query, top_k=top_k * 2)
        bm25_results = self.bm25.search(query, top_k=top_k * 2)

        # Build rank maps: cve_id → rank (1-indexed)
        tfidf_ranks = {r["cve_id"]: i + 1 for i, r in enumerate(tfidf_results)}
        bm25_ranks = {r["cve_id"]: i + 1 for i, r in enumerate(bm25_results)}

        # All candidate CVE IDs
        all_cve_ids = set(tfidf_ranks.keys()) | set(bm25_ranks.keys())

        # Calculate RRF scores
        rrf_scores = {}
        for cve_id in all_cve_ids:
            score = 0.0
            if cve_id in tfidf_ranks:
                score += tfidf_weight * (1.0 / (self.k + tfidf_ranks[cve_id]))
            if cve_id in bm25_ranks:
                score += bm25_weight * (1.0 / (self.k + bm25_ranks[cve_id]))
            rrf_scores[cve_id] = score

        # Sort by RRF score
        sorted_cves = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)[:top_k]

        # Build CVE lookup
        cve_lookup = {e["cve_id"]: e for e in self.cve_entries}

        results = []
        for cve_id, score in sorted_cves:
            entry = cve_lookup[cve_id].copy()
            entry["hybrid_score"] = round(score, 6)
            entry["relevance_score"] = round(score, 6)
            entry["retrieval_method"] = f"Hybrid (TF-IDF×{tfidf_weight} + BM25×{bm25_weight})"
            entry["tfidf_rank"] = tfidf_ranks.get(cve_id, None)
            entry["bm25_rank"] = bm25_ranks.get(cve_id, None)
            results.append(entry)

        return results


# ─────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    with open("data/cve_database.json", "r") as f:
        cves = json.load(f)

    retriever = HybridRetriever(cves)
    print(f"✅ Hybrid index built: {len(cves)} CVEs\n")

    query = "buffer overflow privilege escalation"
    results = retriever.search(query, top_k=5)

    print(f"🔎 Query: \"{query}\"\n")
    for i, r in enumerate(results, 1):
        print(f"  {i}. [RRF: {r['hybrid_score']:.6f}] {r['cve_id']} — {r['type']} ({r['severity']})")
        print(f"     TF-IDF rank: {r['tfidf_rank']}, BM25 rank: {r['bm25_rank']}")
        print()

