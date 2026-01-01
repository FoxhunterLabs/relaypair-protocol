from __future__ import annotations
import hashlib
import hmac
import secrets
import time
from typing import Optional, Tuple

from .constants import ROLE, PROTO_NAME, PROTO_VERSIONS
from .validation import validate_base64
from .encoding import b64e

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hmac_sha256(k: bytes, b: bytes) -> bytes:
    return hmac.new(k, b, hashlib.sha256).digest()

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, n: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t = b"", b""
    c = 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        out += t
        c += 1
    return out[:n]

def safe_compare(a: bytes, b: bytes, expected_length: int = None) -> bool:
    if expected_length and (len(a) != expected_length or len(b) != expected_length):
        return False
    return hmac.compare_digest(a, b)

def sas6(k0: bytes, sid: bytes, profile: str) -> str:
    v = int.from_bytes(sha256(f"{profile}|sas|".encode() + k0 + sid)[:4], "big") % 1_000_000
    return f"{v:06d}"

def derive_nonce_base(master: bytes, sid: bytes, profile: str, role: ROLE) -> bytes:
    """Derive 12-byte nonce base for ChaCha20-Poly1305."""
    return hkdf_sha256(
        master,
        salt=sha256(f"{profile}|nonce-salt|".encode() + sid + b"|" + role.encode()),
        info=f"{profile}|nonce-base|v2".encode(),
        n=12
    )

def build_nonce(nonce_base: bytes, seq2: int) -> bytes:
    """Build nonce by mixing seq2 into nonce_base."""
    seq2_bytes = seq2.to_bytes(8, "big")
    result = bytearray(nonce_base)
    for i in range(4, 12):
        result[i] ^= seq2_bytes[i - 4] if i - 4 < len(seq2_bytes) else 0
    return bytes(result)

def secure_aad(sid: bytes, profile: str, recon_th: bytes, th: bytes, sender: ROLE, seq2: int) -> bytes:
    versions = PROTO_VERSIONS[profile]
    return b"|".join([
        versions["secure"],
        b"proto=" + PROTO_NAME.encode(),
        b"profile=" + profile.encode(),
        b"sid=" + sid,
        b"recon=" + recon_th,
        b"hs=" + th,
        b"sender=" + sender.encode(),
        b"seq2=" + seq2.to_bytes(8, "big"),
    ])

# --- PAKE (SPAKE2) ---

def require_spake2():
    try:
        from spake2 import SPAKE2_A, SPAKE2_B
        return SPAKE2_A, SPAKE2_B
    except ImportError as e:
        raise RuntimeError("Missing dependency 'spake2'") from e

def normalize_password(pin: Optional[str], secret_b64: Optional[str]) -> bytes:
    if (pin is None) == (secret_b64 is None):
        raise ValueError("Provide exactly one of --pin or --secret-b64")

    if pin is not None:
        p = pin.strip()
        if not (6 <= len(p) <= 12) or not p.isdigit():
            raise ValueError("PIN must be 6–12 digits")
        return ("PIN:" + p).encode("utf-8")

    s = validate_base64(secret_b64.strip(), "secret-b64", 16)
    return b"SEC:" + s

def pake_init(role: ROLE, password: bytes, sid: bytes, profile: str):
    SPAKE2_A, SPAKE2_B = require_spake2()
    pw_hash = sha256(f"{profile}|pw|".encode() + sid + b"|" + password)
    sp = SPAKE2_A(pw_hash) if role == "alice" else SPAKE2_B(pw_hash)
    out = sp.start()
    return {"role": role, "sp": sp, "msg_out": out, "profile": profile}

def pake_finish_reduced_timing(pake_state: dict, msg_in: bytes, sid: bytes, profile: str) -> bytes:
    SPAKE2_A, SPAKE2_B = require_spake2()

    dummy_pw = bytearray(sha256(b"dummy|" + sid + b"|" + secrets.token_bytes(8)))
    dummy_sp_cls = SPAKE2_A if pake_state["role"] == "alice" else SPAKE2_B
    dummy_sp = dummy_sp_cls(bytes(dummy_pw))
    dummy_sp.start()
    try:
        dummy_sp.finish(msg_in)
    except Exception:
        pass

    for i in range(len(dummy_pw)):
        dummy_pw[i] = 0

    try:
        k = pake_state["sp"].finish(msg_in)
    except Exception:
        time.sleep(0.03)
        raise ValueError("PAKE failed")

    k0_bytes = hkdf_sha256(
        k,
        salt=sha256(f"{profile}|k0-salt|".encode() + sid),
        info=f"{profile}|K0|v1".encode(),
        n=32
    )
    return k0_bytes

def pake_confirm_tag(k0: bytes, sid: bytes, role: ROLE, transcript_hash: bytes, profile: str) -> bytes:
    return hmac_sha256(
        k0,
        f"{profile}|pake-confirm|".encode() + sid + b"|" + role.encode() + b"|" + transcript_hash
    )

# --- Handshake (X25519) ---

def require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return X25519PrivateKey, X25519PublicKey, Encoding, PublicFormat
    except ImportError as e:
        raise RuntimeError("Missing dependency 'cryptography'") from e

def hs_init(role: ROLE, sid: bytes, profile: str, k0: bytes):
    X25519PrivateKey, _, Encoding, PublicFormat = require_crypto()
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce = secrets.token_bytes(16)
    return {"role": role, "sid": sid, "profile": profile, "priv": priv, "pub_raw": pub, "nonce": nonce, "k0": k0}

def hs_derive_master(hs_state: dict, peer_pub_raw: bytes, peer_nonce: bytes, recon_th: bytes):
    _, X25519PublicKey, _, _ = require_crypto()
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_raw)
    ss = hs_state["priv"].exchange(peer_pub)

    if hs_state["role"] == "alice":
        a_pub, a_nonce = hs_state["pub_raw"], hs_state["nonce"]
        b_pub, b_nonce = peer_pub_raw, peer_nonce
    else:
        a_pub, a_nonce = peer_pub_raw, peer_nonce
        b_pub, b_nonce = hs_state["pub_raw"], hs_state["nonce"]

    versions = PROTO_VERSIONS[hs_state["profile"]]
    tr = b"".join([
        versions["handshake"],
        b"|profile=", hs_state["profile"].encode(),
        b"|sid=", hs_state["sid"],
        b"|recon=", recon_th,
        b"|a=", a_pub, a_nonce,
        b"|b=", b_pub, b_nonce,
    ])
    th = sha256(tr)

    salt = sha256(
        f"{hs_state['profile']}|hs-salt|".encode()
        + hs_state["k0"] + hs_state["sid"] + recon_th + th
    )
    master_bytes = hkdf_sha256(ss, salt=salt, info=f"{hs_state['profile']}|master|v1".encode(), n=32)

    confirm_key = hkdf_sha256(
        master_bytes,
        salt=sha256(f"{hs_state['profile']}|confirm-salt|".encode() + th),
        info=f"{hs_state['profile']}|confirm-key|v1".encode(),
        n=32
    )

    nonce_base_send = derive_nonce_base(master_bytes, hs_state["sid"], hs_state["profile"], hs_state["role"])
    nonce_base_recv = derive_nonce_base(
        master_bytes,
        hs_state["sid"],
        hs_state["profile"],
        "bob" if hs_state["role"] == "alice" else "alice",
    )

    return {"master": master_bytes, "confirm_key": confirm_key, "th": th,
            "nonce_base_send": nonce_base_send, "nonce_base_recv": nonce_base_recv}

def hs_auth_tag(master: bytes, role: ROLE, th: bytes, profile: str) -> bytes:
    return hmac_sha256(master, f"{profile}|hs-auth|".encode() + role.encode() + b"|" + th)

def hs_confirm_tag(confirm_key: bytes, role: ROLE, th: bytes, profile: str) -> bytes:
    return hmac_sha256(confirm_key, f"{profile}|key-confirm|".encode() + role.encode() + b"|" + th)

def derive_session_keys(master: bytes, th: bytes, role: ROLE, profile: str) -> Tuple[bytes, bytes]:
    base = hkdf_sha256(
        master,
        salt=sha256(f"{profile}|kdf|".encode() + th),
        info=f"{profile}|session|v1".encode(),
        n=64
    )
    k1, k2 = base[:32], base[32:]
    return (k1, k2) if role == "alice" else (k2, k1)

# --- AEAD ---

def require_aead():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        return ChaCha20Poly1305
    except ImportError as e:
        raise RuntimeError("Missing dependency 'cryptography'") from e
