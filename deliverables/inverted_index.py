"""
CodeVigil — Week 2 Deliverable: Inverted Index
================================================
Reads the CVE database, tokenizes descriptions, and builds an inverted index.
Run: python deliverables/inverted_index.py
"""

import json
import re
from collections import defaultdict


# ─────────────────────────────────────────────
# STEP 1: Load CVE Database
# ─────────────────────────────────────────────
def load_cve_database(filepath: str) -> list[dict]:
    """Load CVE entries from JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────────────────────────
# STEP 2: Text Preprocessing
# ─────────────────────────────────────────────
STOP_WORDS = {
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "shall",
    "should", "may", "might", "must", "can", "could", "to", "of", "in",
    "for", "on", "with", "at", "by", "from", "as", "into", "through",
    "during", "before", "after", "and", "but", "or", "nor", "not", "so",
    "yet", "both", "either", "neither", "each", "every", "all", "any",
    "few", "more", "most", "other", "some", "such", "no", "only", "own",
    "same", "than", "too", "very", "just", "because", "this", "that",
    "these", "those", "it", "its", "which", "when", "where", "who",
    "whom", "what", "how", "if", "then", "else", "also", "about",
}


def tokenize(text: str) -> list[str]:
    """
    Clean and tokenize text:
    1. Lowercase
    2. Remove special characters (keep alphanumeric)
    3. Split into words
    4. Remove stop words
    5. Remove short tokens (< 2 chars)
    """
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    tokens = text.split()
    tokens = [t for t in tokens if t not in STOP_WORDS and len(t) >= 2]
    return tokens


# ─────────────────────────────────────────────
# STEP 3: Build Inverted Index
# ─────────────────────────────────────────────
def build_inverted_index(cve_entries: list[dict]) -> dict[str, list[str]]:
    """
    Build an inverted index mapping each token to a list of CVE IDs.
    Structure: { "token": ["CVE-XXXX-YYYY", "CVE-AAAA-BBBB", ...] }
    """
    index = defaultdict(list)

    for entry in cve_entries:
        cve_id = entry["cve_id"]
        # Combine description + type + severity for richer indexing
        text = f"{entry['description']} {entry['type']} {entry['severity']}"
        tokens = tokenize(text)

        for token in set(tokens):  # set to avoid duplicates per document
            index[token].append(cve_id)

    # Sort CVE IDs for each token for consistent output
    return {token: sorted(cve_ids) for token, cve_ids in sorted(index.items())}


# ─────────────────────────────────────────────
# STEP 4: Query the Inverted Index
# ─────────────────────────────────────────────
def query_inverted_index(index: dict, query: str) -> list[str]:
    """
    Given a query string, return CVE IDs that contain ANY of the query tokens.
    Uses OR logic (union of all token matches).
    """
    tokens = tokenize(query)
    matching_cves = set()

    for token in tokens:
        if token in index:
            matching_cves.update(index[token])

    return sorted(matching_cves)


# ─────────────────────────────────────────────
# STEP 5: Print Statistics
# ─────────────────────────────────────────────
def print_index_stats(index: dict, cve_entries: list[dict]):
    """Print inverted index statistics."""
    total_tokens = len(index)
    total_postings = sum(len(v) for v in index.values())
    avg_posting_length = total_postings / total_tokens if total_tokens else 0

    print("=" * 60)
    print("  CODEVIGIL — INVERTED INDEX STATISTICS")
    print("=" * 60)
    print(f"  Total CVEs indexed     : {len(cve_entries)}")
    print(f"  Total unique tokens    : {total_tokens}")
    print(f"  Total postings         : {total_postings}")
    print(f"  Avg posting length     : {avg_posting_length:.2f}")
    print("=" * 60)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("\n🔍 CodeVigil — Inverted Index Builder\n")

    # Load data
    db_path = "data/cve_database.json"
    cve_entries = load_cve_database(db_path)
    print(f"✅ Loaded {len(cve_entries)} CVE entries from {db_path}\n")

    # Build inverted index
    index = build_inverted_index(cve_entries)

    # Print stats
    print_index_stats(index, cve_entries)

    # Print first 15 tokens with their postings
    print("\n📋 SAMPLE INVERTED INDEX (first 15 tokens):")
    print("-" * 60)
    for i, (token, cve_ids) in enumerate(sorted(index.items())[:15]):
        print(f"  '{token}' → {cve_ids}")
    print("-" * 60)

    # Demo queries
    print("\n🔎 QUERY DEMONSTRATION:")
    print("-" * 60)
    test_queries = [
        "remote code execution log4j",
        "path traversal file read",
        "SQL injection database",
        "buffer overflow privilege",
        "deserialization arbitrary code",
    ]

    for q in test_queries:
        results = query_inverted_index(index, q)
        print(f"\n  Query: \"{q}\"")
        print(f"  Tokens: {tokenize(q)}")
        print(f"  Results ({len(results)} matches): {results}")

    print("\n✅ Inverted index build complete!")


if __name__ == "__main__":
    main()
