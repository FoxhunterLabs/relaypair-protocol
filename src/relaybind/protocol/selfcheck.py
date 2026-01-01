from __future__ import annotations
import secrets
import sys

from ..core.crypto import require_aead, require_crypto, require_spake2
from ..core.encoding import b64d
from ..core.constants import MIN_PROFILE
from ..protocol.client import profile_allowed

def security_self_check(logger):
    checks = []

    checks.append(("Python >= 3.9", sys.version_info >= (3, 9), "Python 3.9+ required"))

    try:
        test = [secrets.randbits(16) for _ in range(10)]
        checks.append(("Random source", all(x != 0 for x in test), "Weak random detected"))
    except Exception:
        checks.append(("Random source", False, "Random test failed"))

    try:
        require_spake2()
        checks.append(("SPAKE2", True, ""))
    except Exception:
        checks.append(("SPAKE2", False, "spake2 package not installed"))

    try:
        require_crypto()
        checks.append(("Cryptography", True, ""))
    except Exception:
        checks.append(("Cryptography", False, "cryptography package not installed"))

    try:
        require_aead()
        checks.append(("AEAD (ChaCha20Poly1305)", True, ""))
    except Exception:
        checks.append(("AEAD (ChaCha20Poly1305)", False, "AEAD support missing"))

    try:
        b64d("aW52YWxpZCBwYWRkaW5n")
        checks.append(("Base64 strict decode (valid)", True, ""))
    except Exception:
        checks.append(("Base64 strict decode (valid)", False, "Valid base64 rejected"))

    try:
        b64d("invalid!@#$")
        checks.append(("Base64 strict decode (invalid)", False, "Invalid base64 accepted"))
    except ValueError:
        checks.append(("Base64 strict decode (invalid)", True, ""))

    checks.append(("Minimum profile enforcement", profile_allowed(MIN_PROFILE), "Minimum profile not allowed"))

    all_ok = True
    for name, ok, reason in checks:
        all_ok = all_ok and ok
        if ok:
            logger.info("security_check", check=name, status="OK")
        else:
            logger.error("security_check", check=name, status="FAILED", reason=reason)

    if not all_ok:
        raise RuntimeError("Security self-check failed")

    logger.info("security_self_check_passed")
    return True
