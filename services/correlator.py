"""
Eye of Horus — Threat Correlation Engine
Clusters related threats using TF-IDF text similarity, shared IOCs,
temporal proximity, and source relationships.
"""

import re
import hashlib
from datetime import timedelta
from collections import defaultdict

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


# ═══════════════════════════════════════════════════════════════════════════════
#  IOC Extraction
# ═══════════════════════════════════════════════════════════════════════════════

# Regex patterns for common Indicators of Compromise
IOC_PATTERNS = {
    "ipv4": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "domain": r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|tk|ml|ga|cf)\b',
    "cve": r'CVE-\d{4}-\d{4,7}',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
}


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract IOCs from text using regex patterns."""
    if not text:
        return {}
    iocs = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = list(set(re.findall(pattern, text, re.IGNORECASE)))
        if matches:
            iocs[ioc_type] = matches
    return iocs


# ═══════════════════════════════════════════════════════════════════════════════
#  Text Similarity
# ═══════════════════════════════════════════════════════════════════════════════

def compute_text_similarity(texts: list[str], threshold: float = 0.3) -> list[tuple[int, int, float]]:
    """
    Compute pairwise text similarity using TF-IDF cosine similarity.
    Returns list of (idx_a, idx_b, similarity_score) tuples above threshold.
    """
    if len(texts) < 2:
        return []

    # Clean and vectorize
    clean = [t if t else "" for t in texts]
    vectorizer = TfidfVectorizer(
        max_features=500, stop_words="english",
        min_df=1, max_df=0.95,
    )

    try:
        tfidf_matrix = vectorizer.fit_transform(clean)
    except ValueError:
        return []

    # Compute cosine similarity
    sim_matrix = cosine_similarity(tfidf_matrix)

    # Extract pairs above threshold
    edges = []
    n = len(texts)
    for i in range(n):
        for j in range(i + 1, n):
            if sim_matrix[i, j] >= threshold:
                edges.append((i, j, round(float(sim_matrix[i, j]), 3)))

    return edges


# ═══════════════════════════════════════════════════════════════════════════════
#  Threat Clustering
# ═══════════════════════════════════════════════════════════════════════════════

def cluster_threats(df: pd.DataFrame, sim_threshold: float = 0.3) -> dict:
    """
    Cluster threats by text similarity, shared IOCs, and temporal proximity.
    Returns dict with clusters, edges, and IOC data.
    """
    if df.empty or len(df) < 2:
        return {"clusters": [], "edges": [], "iocs": {}}

    # Limit for performance
    work_df = df.head(200).copy()
    texts = (work_df.get("title", pd.Series(dtype=str)).fillna("") + " " +
             work_df.get("text", pd.Series(dtype=str)).fillna("")).tolist()

    # Text similarity edges
    text_edges = compute_text_similarity(texts, threshold=sim_threshold)

    # IOC extraction and correlation
    iocs_per_record = []
    for text in texts:
        iocs_per_record.append(extract_iocs(text))

    # Find shared IOC edges
    ioc_edges = []
    for i in range(len(iocs_per_record)):
        for j in range(i + 1, len(iocs_per_record)):
            shared = _count_shared_iocs(iocs_per_record[i], iocs_per_record[j])
            if shared > 0:
                ioc_edges.append((i, j, shared))

    # Merge edges (text sim + IOC correlation)
    edge_map = {}
    for i, j, score in text_edges:
        edge_map[(i, j)] = {"text_sim": score, "shared_iocs": 0, "type": "text"}
    for i, j, count in ioc_edges:
        key = (min(i, j), max(i, j))
        if key in edge_map:
            edge_map[key]["shared_iocs"] = count
            edge_map[key]["type"] = "both"
        else:
            edge_map[key] = {"text_sim": 0, "shared_iocs": count, "type": "ioc"}

    # Build cluster assignments via union-find
    clusters = _union_find_clusters(len(work_df), list(edge_map.keys()))

    return {
        "df": work_df,
        "edges": edge_map,
        "clusters": clusters,
        "iocs": {i: iocs for i, iocs in enumerate(iocs_per_record) if iocs},
    }


def _count_shared_iocs(a: dict, b: dict) -> int:
    """Count shared IOC values between two IOC dicts."""
    shared = 0
    for ioc_type in a:
        if ioc_type in b:
            shared += len(set(a[ioc_type]) & set(b[ioc_type]))
    return shared


def _union_find_clusters(n: int, edges: list[tuple[int, int]]) -> list[list[int]]:
    """Simple union-find to group connected nodes into clusters."""
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for i, j in edges:
        union(i, j)

    groups = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(i)

    # Only return clusters with 2+ members
    return [members for members in groups.values() if len(members) >= 2]
