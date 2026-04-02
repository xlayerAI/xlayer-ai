"""
engine/dedup.py — SimHash Target Deduplication

Deduplicates endpoints before AgentSpawner to avoid wasting solver budget
on identical or near-identical pages (e.g. /product/1, /product/2, /product/3).

Uses SimHash (locality-sensitive hashing) to detect near-duplicate HTML responses.
Endpoints with Hamming distance < threshold are clustered as duplicates;
only one representative from each cluster is kept.

Called by Coordinator after LSM, before AgentSpawner.
"""

import asyncio
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from loguru import logger

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


@dataclass
class DeduplicationResult:
    """Result of endpoint deduplication."""
    unique_endpoints: List[str]
    duplicates_removed: List[str]
    clusters: Dict[str, List[str]]  # representative → list of duplicates
    total_before: int = 0
    total_after: int = 0


class TargetDeduplicator:
    """
    SimHash-based endpoint deduplication.

    Fetches each endpoint, computes SimHash of HTML response,
    clusters by Hamming distance, keeps one representative per cluster.
    """

    def __init__(
        self,
        hamming_threshold: int = 3,
        timeout: int = 10,
        max_fetch: int = 200,
        proxy: Optional[str] = None,
    ):
        self.hamming_threshold = hamming_threshold
        self.timeout = timeout
        self.max_fetch = max_fetch
        self.proxy = proxy

    async def deduplicate(
        self, endpoints: Dict[str, object]
    ) -> DeduplicationResult:
        """
        Deduplicate endpoints by HTML SimHash similarity.

        Args:
            endpoints: dict of {url: EndpointNode} from LogicalSurface

        Returns:
            DeduplicationResult with unique/duplicate lists and clusters
        """
        urls = list(endpoints.keys())[:self.max_fetch]
        total_before = len(urls)

        if total_before <= 1:
            return DeduplicationResult(
                unique_endpoints=urls,
                duplicates_removed=[],
                clusters={},
                total_before=total_before,
                total_after=total_before,
            )

        # Fetch HTML for each endpoint
        hashes = await self._fetch_and_hash(urls)

        if not hashes:
            return DeduplicationResult(
                unique_endpoints=urls,
                duplicates_removed=[],
                clusters={},
                total_before=total_before,
                total_after=total_before,
            )

        # Cluster by Hamming distance
        clusters = self._cluster_by_hamming(hashes)

        unique = []
        removed = []
        cluster_map = {}

        for representative, members in clusters.items():
            unique.append(representative)
            dupes = [m for m in members if m != representative]
            if dupes:
                cluster_map[representative] = dupes
                removed.extend(dupes)

        # Also include endpoints that we couldn't fetch (keep them)
        fetched_urls = set(hashes.keys())
        for url in urls:
            if url not in fetched_urls and url not in unique:
                unique.append(url)

        logger.info(
            f"[Dedup] {total_before} → {len(unique)} endpoints "
            f"({len(removed)} duplicates removed, {len(clusters)} clusters)"
        )

        return DeduplicationResult(
            unique_endpoints=unique,
            duplicates_removed=removed,
            clusters=cluster_map,
            total_before=total_before,
            total_after=len(unique),
        )

    async def _fetch_and_hash(self, urls: List[str]) -> Dict[str, int]:
        """Fetch HTML for each URL and compute SimHash."""
        if not _HAS_HTTPX:
            return {}

        hashes: Dict[str, int] = {}
        semaphore = asyncio.Semaphore(20)

        async def _fetch_one(url: str):
            async with semaphore:
                try:
                    client_kwargs = {
                        "follow_redirects": True,
                        "timeout": self.timeout,
                        "verify": False,
                    }
                    if self.proxy:
                        client_kwargs["proxy"] = self.proxy

                    async with httpx.AsyncClient(**client_kwargs) as client:
                        resp = await client.get(url)
                        if resp.status_code < 400:
                            html = resp.text[:10000]  # first 10KB
                            hashes[url] = self._simhash(html)
                except Exception:
                    pass

        await asyncio.gather(*[_fetch_one(u) for u in urls])
        return hashes

    def _cluster_by_hamming(
        self, hashes: Dict[str, int]
    ) -> Dict[str, List[str]]:
        """Cluster URLs whose SimHashes have Hamming distance < threshold."""
        urls = list(hashes.keys())
        assigned: Set[str] = set()
        clusters: Dict[str, List[str]] = {}

        for i, url_a in enumerate(urls):
            if url_a in assigned:
                continue

            cluster = [url_a]
            assigned.add(url_a)

            for j in range(i + 1, len(urls)):
                url_b = urls[j]
                if url_b in assigned:
                    continue

                dist = self._hamming_distance(hashes[url_a], hashes[url_b])
                if dist <= self.hamming_threshold:
                    cluster.append(url_b)
                    assigned.add(url_b)

            clusters[url_a] = cluster

        return clusters

    @staticmethod
    def _simhash(text: str, hashbits: int = 64) -> int:
        """
        Compute SimHash of text.

        Tokenizes into shingles (3-grams), hashes each shingle,
        accumulates weighted bit vectors, returns final hash.
        """
        # Normalize: lowercase, strip tags, collapse whitespace
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text.lower().strip())

        if not text:
            return 0

        # Generate 3-character shingles
        tokens = [text[i:i+3] for i in range(max(1, len(text) - 2))]

        # Accumulate bit weights
        v = [0] * hashbits
        for token in tokens:
            h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
            for i in range(hashbits):
                bitmask = 1 << i
                if h & bitmask:
                    v[i] += 1
                else:
                    v[i] -= 1

        # Build final hash
        fingerprint = 0
        for i in range(hashbits):
            if v[i] > 0:
                fingerprint |= (1 << i)

        return fingerprint

    @staticmethod
    def _hamming_distance(a: int, b: int) -> int:
        """Count differing bits between two integers."""
        return bin(a ^ b).count("1")
