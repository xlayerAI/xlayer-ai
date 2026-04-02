"""
Request pacing (jitter) — configurable random delay between requests.
WAF evasion: human-like spacing instead of burst traffic.
"""

import asyncio
import random
from typing import Optional


async def apply_pacing() -> None:
    """
    If pacing jitter is configured (scan.pacing_jitter_min_sec/max_sec > 0),
    sleep a random duration before the next request.
    Call this at the start of any HTTP request path (http_client, http_probe, validator).
    """
    try:
        from xlayer_ai.config.settings import get_settings
        settings = get_settings()
        scan = getattr(settings, "scan", None)
        if not scan:
            return
        min_sec = getattr(scan, "pacing_jitter_min_sec", 0.0) or 0.0
        max_sec = getattr(scan, "pacing_jitter_max_sec", 0.0) or 0.0
        if max_sec > 0 and max_sec >= min_sec:
            delay = random.uniform(min_sec, max_sec)
            await asyncio.sleep(delay)
    except Exception:
        pass
