"""
CodeVigil — TF-IDF Retriever
=============================
Implements TF-IDF vectorization + cosine similarity for vulnerability search.
"""

import json
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np


class TFIDFRetriever:
    """
    TF-IDF based vulnerability retriever.
    
    Converts CVE descriptions into TF-IDF vectors and uses
    cosine similarity to rank results for a given query.
    """

    def __init__(self, cve_entries: list[dict]):
        """Initialize with CVE entries and build the TF-IDF index."""
        self.cve_entries = cve_entries
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words="english",
            ngram_range=(1, 2),  # unigrams + bigrams
            min_df=1,
            max_df=0.95,
            sublinear_tf=True,  # apply log normalization to TF
        )

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

        # Fit and transform corpus into TF-IDF matrix
        self.tfidf_matrix = self.vectorizer.fit_transform(self.corpus)

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        """
        Search for vulnerabilities matching the query.
        
        Args:
            query: User's search query (natural language or code snippet)
            top_k: Number of results to return
            
        Returns:
            List of dicts with CVE info + relevance score
        """
        # Transform query into TF-IDF vector
        query_vector = self.vectorizer.transform([query])

        # Compute cosine similarity between query and all documents
        similarities = cosine_similarity(query_vector, self.tfidf_matrix).flatten()

        # Get top-k indices sorted by similarity (descending)
        top_indices = np.argsort(similarities)[::-1][:top_k]

        results = []
        for idx in top_indices:
            if similarities[idx] > 0:  # Only return non-zero matches
                entry = self.cve_entries[idx].copy()
                entry["relevance_score"] = round(float(similarities[idx]), 4)
                entry["retrieval_method"] = "TF-IDF + Cosine Similarity"
                results.append(entry)

        return results

    def get_vocabulary(self) -> list[str]:
        """Return the TF-IDF vocabulary (feature names)."""
        return self.vectorizer.get_feature_names_out().tolist()

    def get_tfidf_scores(self, doc_index: int) -> list[tuple[str, float]]:
        """Return top TF-IDF terms for a specific document."""
        feature_names = self.vectorizer.get_feature_names_out()
        doc_scores = self.tfidf_matrix[doc_index].toarray().flatten()
        
        # Sort by score descending
        scored_terms = list(zip(feature_names, doc_scores))
        scored_terms.sort(key=lambda x: x[1], reverse=True)
        
        return scored_terms[:20]  # Top 20 terms


# ─────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    with open("data/cve_database.json", "r") as f:
        cves = json.load(f)

    retriever = TFIDFRetriever(cves)
    print(f"✅ TF-IDF index built: {len(cves)} CVEs, {len(retriever.get_vocabulary())} features\n")

    query = "log4j remote code execution"
    results = retriever.search(query, top_k=5)

    print(f"🔎 Query: \"{query}\"\n")
    for i, r in enumerate(results, 1):
        print(f"  {i}. [{r['relevance_score']:.4f}] {r['cve_id']} — {r['type']} ({r['severity']})")
        print(f"     {r['description'][:100]}...")
        print()
