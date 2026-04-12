"""
Base template classes and randomization utilities for data generation.
"""

import random
from typing import List, Dict, Any, Tuple


COMPLEXITY_LEVELS = ["beginner", "intermediate", "advanced", "expert"]


def pick_complexity(rng: random.Random, weights: Dict[str, float]) -> str:
    levels = list(weights.keys())
    w = [weights[l] for l in levels]
    return rng.choices(levels, weights=w, k=1)[0]


def pick_severity(rng: random.Random, complexity: str) -> str:
    if complexity == "beginner":
        return rng.choice(["low", "medium", "medium"])
    elif complexity == "intermediate":
        return rng.choice(["medium", "medium", "high"])
    elif complexity == "advanced":
        return rng.choice(["medium", "high", "high", "critical"])
    else:
        return rng.choice(["high", "critical", "critical"])


def rand_ip(rng: random.Random, internal: bool = False) -> str:
    if internal:
        return f"10.{rng.randint(0,255)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
    return f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def rand_port(rng: random.Random) -> int:
    return rng.choice([22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017,
                       rng.randint(1024, 65535)])


def rand_domain(rng: random.Random) -> str:
    prefixes = ["app", "api", "portal", "dashboard", "admin", "auth", "cdn",
                "staging", "dev", "internal", "mail", "vpn", "git", "ci"]
    tlds = ["example.com", "corp.local", "acme.io", "testorg.net", "securebank.com",
            "healthapp.io", "retailshop.com", "cloudservice.dev"]
    return f"{rng.choice(prefixes)}.{rng.choice(tlds)}"


def rand_username(rng: random.Random) -> str:
    names = ["admin", "jdoe", "alice", "bob", "sysadmin", "devops", "deploy",
             "jenkins", "root", "webapp", "service_account", "api_user"]
    return rng.choice(names)


def rand_path(rng: random.Random) -> str:
    segments = ["api", "v1", "v2", "users", "admin", "uploads", "files",
                "config", "internal", "debug", "health", "login", "auth",
                "dashboard", "export", "import", "webhook", "callback"]
    depth = rng.randint(2, 4)
    return "/" + "/".join(rng.sample(segments, depth))


def rand_var_name(rng: random.Random, context: str = "generic") -> str:
    pools = {
        "generic": ["data", "result", "value", "item", "payload", "content", "buf"],
        "user": ["user_id", "username", "email", "account_id", "profile_id", "customer_id"],
        "db": ["query", "stmt", "sql", "cursor", "conn", "db_result", "rows"],
        "web": ["request", "response", "req", "res", "body", "params", "headers"],
        "file": ["filename", "filepath", "upload_path", "file_data", "document"],
        "auth": ["token", "session_id", "api_key", "password", "credential", "secret"],
    }
    return rng.choice(pools.get(context, pools["generic"]))


def rand_table_name(rng: random.Random) -> str:
    return rng.choice(["users", "accounts", "orders", "products", "sessions",
                       "transactions", "customers", "employees", "invoices",
                       "audit_log", "permissions", "roles", "payments"])


def rand_func_name(rng: random.Random, action: str = "process") -> str:
    actions = ["get", "fetch", "process", "handle", "validate", "parse",
               "check", "load", "update", "create", "delete", "find"]
    objects = ["user", "data", "request", "input", "record", "file",
               "query", "config", "session", "token", "order", "payment"]
    a = action if action != "process" else rng.choice(actions)
    return f"{a}_{rng.choice(objects)}"


def format_entry(entry_id: str, title: str, severity: str, cwe: str,
                 instruction: str, input_text: str, output_text: str) -> Dict[str, Any]:
    return {
        "id": entry_id,
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "instruction": instruction,
        "input": input_text,
        "output": output_text,
    }


class CategoryGenerator:
    """Base class for all category generators."""

    category: str = ""
    id_prefix: str = ""

    def make_id(self, idx: int) -> str:
        return f"{self.id_prefix}-{idx:05d}"

    def generate_entries(self, rng: random.Random, count: int, start_id: int,
                         complexity_weights: Dict[str, float]) -> List[Dict[str, Any]]:
        raise NotImplementedError
