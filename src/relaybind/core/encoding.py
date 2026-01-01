import base64
from .constants import MAX_B64_LENGTH

def b64e(b: bytes) -> str:
    """Encode bytes to strict base64."""
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    """Decode strict base64 with validation."""
    if len(s) > MAX_B64_LENGTH:
        raise ValueError(f"Base64 too long: {len(s)} > {MAX_B64_LENGTH}")
    return base64.b64decode(s, validate=True)
