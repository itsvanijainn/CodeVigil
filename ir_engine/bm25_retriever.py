"""
CodeVigil — BM25 Retriever
============================
Implements Okapi BM25 ranking for vulnerability search.
Uses the rank-bm25 library.
"""

import json
import re
from rank_bm25 import BM25Okapi


class BM25Retriever:
    """
    BM25-based vulnerability retriever.
    
    Uses the Okapi BM25 algorithm for ranking documents
    based on term frequency and inverse document frequency.
    """

    def __init__(self, cve_entries: list[dict]):
        """Initialize with CVE entries and build the BM25 index."""
        self.cve_entries = cve_entries

        # Build corpus: combine description + type + severity + affected_software
        self.corpus = []
        for entry in cve_entries:
            text = (
                f"{entry['description']} "
                f"{entry['type']} "
                f"{entry['severity']} "
                f"{entry.get('affected_software', '')}"
            )
            self.corpus.append(text)

        # Tokenize corpus
        tokenized_corpus = [self._tokenize(doc) for doc in self.corpus]

        # Build BM25 index
        self.bm25 = BM25Okapi(tokenized_corpus)

    def _tokenize(self, text: str) -> list[str]:
        """Simple tokenization: lowercase + split on non-alphanumeric."""
        text = text.lower()
        text = re.sub(r"[^a-z0-9\s]", " ", text)
        return text.split()

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        """
        Search for vulnerabilities using BM25 ranking.
        
        Args:
            query: User's search query
            top_k: Number of results to return
            
        Returns:
            List of dicts with CVE info + BM25 score
        """
        tokenized_query = self._tokenize(query)

        # Get BM25 scores for all documents
        scores = self.bm25.get_scores(tokenized_query)

        # Normalize scores to 0-1 range for comparison
        max_score = max(scores) if max(scores) > 0 else 1
        normalized_scores = scores / max_score

        # Get top-k indices sorted by score (descending)
        top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:top_k]

        results = []
        for idx in top_indices:
            if scores[idx] > 0:
                entry = self.cve_entries[idx].copy()
                entry["bm25_score"] = round(float(scores[idx]), 4)
                entry["relevance_score"] = round(float(normalized_scores[idx]), 4)
                entry["retrieval_method"] = "BM25 (Okapi)"
                results.append(entry)

        return results


# ─────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    with open("data/cve_database.json", "r") as f:
        cves = json.load(f)

    retriever = BM25Retriever(cves)
    print(f"✅ BM25 index built: {len(cves)} CVEs\n")

    query = "log4j remote code execution"
    results = retriever.search(query, top_k=5)

    print(f"🔎 Query: \"{query}\"\n")
    for i, r in enumerate(results, 1):
        print(f"  {i}. [BM25: {r['bm25_score']:.4f}] {r['cve_id']} — {r['type']} ({r['severity']})")
        print(f"     {r['description'][:100]}...")
        print()
