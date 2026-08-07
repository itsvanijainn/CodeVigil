"""
CodeVigil — Evaluation Metrics
================================
Implements standard IR evaluation metrics:
- Precision@K
- Recall@K
- Mean Reciprocal Rank (MRR)
- F1@K
"""


def precision_at_k(retrieved_ids: list[str], relevant_ids: list[str], k: int = 5) -> float:
    """
    Precision@K = (# relevant docs in top-k) / K
    
    Args:
        retrieved_ids: List of retrieved CVE IDs (ordered by relevance)
        relevant_ids: List of ground-truth relevant CVE IDs
        k: Number of top results to consider
        
    Returns:
        Precision score (0.0 to 1.0)
    """
    if k == 0:
        return 0.0
    
    top_k = retrieved_ids[:k]
    relevant_set = set(relevant_ids)
    relevant_in_top_k = sum(1 for doc_id in top_k if doc_id in relevant_set)
    
    return relevant_in_top_k / k


def recall_at_k(retrieved_ids: list[str], relevant_ids: list[str], k: int = 5) -> float:
    """
    Recall@K = (# relevant docs in top-k) / (total relevant docs)
    """
    if len(relevant_ids) == 0:
        return 0.0
    
    top_k = retrieved_ids[:k]
    relevant_set = set(relevant_ids)
    relevant_in_top_k = sum(1 for doc_id in top_k if doc_id in relevant_set)
    
    return relevant_in_top_k / len(relevant_set)


def f1_at_k(retrieved_ids: list[str], relevant_ids: list[str], k: int = 5) -> float:
    """
    F1@K = 2 * (Precision@K * Recall@K) / (Precision@K + Recall@K)
    """
    p = precision_at_k(retrieved_ids, relevant_ids, k)
    r = recall_at_k(retrieved_ids, relevant_ids, k)
    
    if p + r == 0:
        return 0.0
    
    return 2 * (p * r) / (p + r)


def mean_reciprocal_rank(queries_results: list[tuple[list[str], list[str]]]) -> float:
    """
    Mean Reciprocal Rank (MRR).
    
    For each query, find the rank of the first relevant document.
    MRR = (1/|Q|) * Σ (1 / rank_i)
    
    Args:
        queries_results: List of (retrieved_ids, relevant_ids) tuples
        
    Returns:
        MRR score (0.0 to 1.0)
    """
    if not queries_results:
        return 0.0
    
    reciprocal_ranks = []
    
    for retrieved_ids, relevant_ids in queries_results:
        relevant_set = set(relevant_ids)
        rr = 0.0
        
        for rank, doc_id in enumerate(retrieved_ids, 1):
            if doc_id in relevant_set:
                rr = 1.0 / rank
                break
        
        reciprocal_ranks.append(rr)
    
    return sum(reciprocal_ranks) / len(reciprocal_ranks)


def average_precision(retrieved_ids: list[str], relevant_ids: list[str]) -> float:
    """
    Average Precision (AP) for a single query.
    
    AP = (1/|relevant|) * Σ (Precision@k * rel(k))
    where rel(k) = 1 if doc at rank k is relevant, 0 otherwise.
    """
    relevant_set = set(relevant_ids)
    
    if len(relevant_set) == 0:
        return 0.0
    
    precision_sum = 0.0
    relevant_count = 0
    
    for rank, doc_id in enumerate(retrieved_ids, 1):
        if doc_id in relevant_set:
            relevant_count += 1
            precision_at_this_rank = relevant_count / rank
            precision_sum += precision_at_this_rank
    
    return precision_sum / len(relevant_set)


def mean_average_precision(queries_results: list[tuple[list[str], list[str]]]) -> float:
    """
    Mean Average Precision (MAP).
    
    MAP = (1/|Q|) * Σ AP_i
    """
    if not queries_results:
        return 0.0
    
    aps = [average_precision(ret, rel) for ret, rel in queries_results]
    return sum(aps) / len(aps)


# ─────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # Example evaluation
    retrieved = ["CVE-2021-44228", "CVE-2017-5638", "CVE-2019-0708", "CVE-2021-41773", "CVE-2014-0160"]
    relevant = ["CVE-2021-44228", "CVE-2021-41773", "CVE-2021-42013"]
    
    print("=" * 50)
    print("  IR EVALUATION METRICS DEMO")
    print("=" * 50)
    print(f"\n  Retrieved: {retrieved}")
    print(f"  Relevant:  {relevant}")
    print()
    print(f"  Precision@3  : {precision_at_k(retrieved, relevant, 3):.4f}")
    print(f"  Precision@5  : {precision_at_k(retrieved, relevant, 5):.4f}")
    print(f"  Recall@3     : {recall_at_k(retrieved, relevant, 3):.4f}")
    print(f"  Recall@5     : {recall_at_k(retrieved, relevant, 5):.4f}")
    print(f"  F1@5         : {f1_at_k(retrieved, relevant, 5):.4f}")
    print(f"  AP           : {average_precision(retrieved, relevant):.4f}")
    
    # MRR demo with multiple queries
    queries = [
        (retrieved, relevant),
        (["CVE-2019-0708", "CVE-2021-44228"], ["CVE-2019-0708"]),
        (["CVE-2014-0160", "CVE-2020-1472"], ["CVE-2021-44228"]),
    ]
    print(f"\n  MRR (3 queries): {mean_reciprocal_rank(queries):.4f}")
    print(f"  MAP (3 queries): {mean_average_precision(queries):.4f}")
    print("=" * 50)
