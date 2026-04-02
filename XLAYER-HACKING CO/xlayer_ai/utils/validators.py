"""
XLayer AI Validators - Input validation utilities
"""

import re
from urllib.parse import urlparse
from typing import Optional, List, Tuple


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a URL for scanning
    
    Args:
        url: URL to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url:
        return False, "URL cannot be empty"
    
    try:
        parsed = urlparse(url)
        
        if parsed.scheme not in ("http", "https"):
            return False, f"Invalid scheme: {parsed.scheme}. Must be http or https"
        
        if not parsed.netloc:
            return False, "URL must have a hostname"
        
        hostname = parsed.netloc.split(":")[0]
        
        private_patterns = [
            r"^localhost$",
            r"^127\.",
            r"^10\.",
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
            r"^192\.168\.",
            r"^0\.",
            r"^169\.254\.",
        ]
        
        for pattern in private_patterns:
            if re.match(pattern, hostname):
                return False, f"Private/local addresses not allowed: {hostname}"
        
        return True, None
        
    except Exception as e:
        return False, f"Invalid URL format: {str(e)}"


def validate_scope(target_url: str, test_url: str) -> bool:
    """
    Check if a URL is within the scope of the target
    
    Args:
        target_url: The original target URL
        test_url: URL to check
        
    Returns:
        True if test_url is in scope
    """
    try:
        target_parsed = urlparse(target_url)
        test_parsed = urlparse(test_url)
        
        target_domain = target_parsed.netloc.lower()
        test_domain = test_parsed.netloc.lower()
        
        if target_domain.startswith("www."):
            target_domain = target_domain[4:]
        if test_domain.startswith("www."):
            test_domain = test_domain[4:]
        
        return test_domain == target_domain or test_domain.endswith(f".{target_domain}")
        
    except Exception:
        return False


def sanitize_filename(filename: str) -> str:
    """Sanitize a string for use as a filename"""
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    sanitized = sanitized[:200]
    return sanitized


def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return None


def is_same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs have the same origin"""
    try:
        p1 = urlparse(url1)
        p2 = urlparse(url2)
        return (p1.scheme == p2.scheme and p1.netloc == p2.netloc)
    except Exception:
        return False
