from __future__ import annotations
import json
from typing import Any, Dict

from .constants import MAX_MSG_BYTES, MAX_JSON_DEPTH, MAX_JSON_KEYS
from .encoding import b64d

def validate_bytes_length(data: bytes, name: str, min_len: int, max_len: int = None):
    if len(data) < min_len:
        raise ValueError(f"{name} too short: {len(data)} < {min_len}")
    if max_len and len(data) > max_len:
        raise ValueError(f"{name} too long: {len(data)} > {max_len}")

def validate_base64(s: str, name: str, min_bytes: int, max_bytes: int = None) -> bytes:
    """Validate base64 with strict decoding."""
    try:
        data = b64d(s)
        validate_bytes_length(data, name, min_bytes, max_bytes)
        return data
    except Exception as e:
        raise ValueError(f"Invalid base64 for {name}: {e}")

def fuzz_resistant_json_loads(s: str) -> Dict[str, Any]:
    if len(s) > MAX_MSG_BYTES * 2:
        raise ValueError("Message too large")

    def object_hook(obj):
        if len(obj) > MAX_JSON_KEYS:
            raise ValueError("Too many JSON keys")
        return obj

    parsed = json.loads(s, object_hook=object_hook)

    def check_depth(obj, depth=0):
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON nesting too deep")
        if isinstance(obj, dict):
            for v in obj.values():
                check_depth(v, depth + 1)
        elif isinstance(obj, list):
            for v in obj:
                check_depth(v, depth + 1)

    check_depth(parsed)
    if not isinstance(parsed, dict):
        raise ValueError("Message must be JSON object")
    return parsed

def json_dumps_sorted(o: Any) -> str:
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
