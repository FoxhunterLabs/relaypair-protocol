from __future__ import annotations

import asyncio
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.constants import (
    ROLE, PROTO_NAME, PROTO_VER,
    SUPPORTED_PROFILES, MIN_PROFILE, PROFILE_RANKS,
    REQUIRE_SEQ_MONOTONIC, MAX_DECRYPT_FAILURES,
    AbortCode, KINDS
)
from ..core.errors import ProtocolError
from ..core.validation import fuzz_resistant_json_loads, json_dumps_sorted
from ..core.validation import validate_base64
from ..core.encoding import b64e
from ..core.transcript import Transcript
from ..core.crypto import (
    safe_compare, sas6,
    pake_init, pake_finish_reduced_timing, pake_confirm_tag,
    hs_init, hs_derive_master, hs_auth_tag, hs_confirm_tag, derive_session_keys,
    require_aead, build_nonce, secure_aad
)
from .state import Phase

def profile_allowed(profile: str) -> bool:
    if profile not in PROFILE_RANKS:
        return False
    return PROFILE_RANKS[profile] >= PROFILE_RANKS[MIN_PROFILE]

def negotiate_profile(my_profiles: List[str], peer_profiles: List[str]) -> str:
    for profile in sorted(my_profiles, key=lambda p: PROFILE_RANKS.get(p, 0), reverse=True):
        if profile in peer_profiles and profile_allowed(profile):
            return profile
    raise ValueError("No mutually supported profile")

@dataclass
class ClientState:
    role: ROLE
    sid: bytes
    profile: Optional[str] = None
    phase: Phase = Phase.INIT
    seq_out: int = 0
    peer_seq_in: int = 0
    transcript: Optional[Transcript] = None
    recon_th: Optional[bytes] = None
    k0: Optional[bytes] = None
    master: Optional[bytes] = None
    th: Optional[bytes] = None
    nonce_base_send: Optional[bytes] = None
    nonce_base_recv: Optional[bytes] = None
    send_key: Optional[bytes] = None
    recv_key: Optional[bytes] = None
    send_seq2: int = 0
    recv_seq2: int = 0

    peer_pake_confirm: Optional[bytes] = None
    peer_hs_auth: Optional[bytes] = None
    peer_hs_confirm: Optional[bytes] = None

    inbox: Dict[str, List[Dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))

    peer_conn_id: Optional[str] = None

    decrypt_failures: int = 0
    last_decrypt_failure: float = 0.0

    def cleanup(self):
        for field_name in ["k0", "master", "send_key", "recv_key", "nonce_base_send", "nonce_base_recv"]:
            val = getattr(self, field_name)
            if isinstance(val, bytes):
                setattr(self, field_name, None)
        self.phase = Phase.ABORTED

class WSClient:
    def __init__(self, url: str, session_code: str, role: ROLE, password: bytes, logger):
        self.url = url.rstrip("/")
        self.code = session_code
        self.role = role
        self.peer: ROLE = "bob" if role == "alice" else "alice"
        self.password = password
        self.logger = logger

        self.ws = None
        self.state = ClientState(role=role, sid=b"")
        self._pending: Dict[str, asyncio.Future] = {}
        self._out_of_order_count = 0
        self._pake_state = None
        self._hs_state = None

        self._rx_task: Optional[asyncio.Task] = None
        self._rx_queue: asyncio.Queue = asyncio.Queue()
        self._running = False

    async def connect(self):
        try:
            import websockets
        except ImportError as e:
            raise RuntimeError("Missing dependency 'websockets'") from e

        ws_url = f"{self.url}/ws/{self.code}/{self.role}"
        self.ws = await websockets.connect(ws_url)

        self._running = True
        self._rx_task = asyncio.create_task(self._recv_loop())

        msg = await self._wait_for_message(lambda m: m.get("type") == "hello")
        if not msg:
            raise ProtocolError("expected hello")

        if msg.get("proto") != PROTO_NAME or msg.get("ver") != PROTO_VER:
            raise ProtocolError("protocol mismatch")

        payload = msg.get("payload", {})
        self.state.sid = validate_base64(payload["session_id_b64"], "sid", 16, 16)
        self.state.phase = Phase.CONNECTED

        self.logger.info("client_connected", role=self.role, session=self.code)

    async def _recv_loop(self):
        while self._running and self.ws:
            try:
                raw = await self.ws.recv()
                msg = fuzz_resistant_json_loads(raw)

                if msg.get("proto") != PROTO_NAME or msg.get("ver") != PROTO_VER:
                    self.logger.error("protocol_mismatch", message=msg)
                    continue

                await self._rx_queue.put(msg)
            except Exception as e:
                if self._running:
                    self.logger.error("recv_loop_error", error=str(e))
                break

    async def _wait_for_message(self, condition) -> Optional[Dict[str, Any]]:
        start_time = time.time()
        timeout = 30.0

        while self._running and (time.time() - start_time < timeout):
            try:
                if not self._rx_queue.empty():
                    msg = self._rx_queue.get_nowait()
                    if condition(msg):
                        return msg
                    await self._process_received_message(msg)
                else:
                    try:
                        msg = await asyncio.wait_for(self._rx_queue.get(), timeout=0.1)
                        if condition(msg):
                            return msg
                        await self._process_received_message(msg)
                    except asyncio.TimeoutError:
                        continue
            except Exception as e:
                self.logger.error("wait_for_message_error", error=str(e))
                break

        return None

    def _validate_message_phase(self, kind: str) -> bool:
        phase = self.state.phase

        if kind == "profile_hello":
            return phase in [Phase.CONNECTED, Phase.PROFILE_NEGOTIATING]

        if kind == "pake_hello":
            return phase == Phase.PAKE
        if kind == "pake_confirm":
            return phase in [Phase.PAKE, Phase.PAKE_DONE]

        if kind == "hs_hello":
            return phase == Phase.HANDSHAKING
        if kind in ["hs_auth", "hs_confirm"]:
            return phase in [Phase.HANDSHAKING, Phase.HANDSHAKE_AUTHED]

        if kind == "secure_msg":
            return phase == Phase.ESTABLISHED

        if kind == "abort":
            return True

        return False

    async def _process_received_message(self, msg: Dict[str, Any]):
        msg_type = msg.get("type")

        if msg_type == "relay":
            wrapper = msg.get("payload", {})
            from_role = wrapper.get("from", self.peer)
            peer_msg = wrapper.get("msg", {})
            await self._handle_peer(from_role, peer_msg)
        elif msg_type == "error":
            raise ProtocolError(f"relay error: {msg.get('payload')}")
        elif msg_type == "peer_joined":
            self.logger.info("peer_connected", role=self.role, peer=self.peer)
            self.state.peer_seq_in = 0
            self.state.peer_conn_id = None
        elif msg_type == "peer_left":
            self.logger.info("peer_disconnected", role=self.role, peer=self.peer)

    async def _send_raw(self, o: Dict[str, Any]):
        if not self.ws:
            raise ProtocolError("not connected")
        o["proto"] = PROTO_NAME
        o["ver"] = PROTO_VER
        await self.ws.send(json_dumps_sorted(o))

    async def send_packet(self, kind: str, payload: Dict[str, Any], op: str = "req"):
        self.state.seq_out += 1
        seq = self.state.seq_out

        wire_payload = {("rid" if k == "id" else k): v for k, v in payload.items()}
        p = {"kind": kind, "seq": seq, "op": op, **wire_payload}

        if self.state.transcript:
            self.state.transcript.record(self.role, kind, seq, p)

        await self._send_raw({"type": "packet", "payload": p})

    async def request(self, kind: str, payload: Dict[str, Any], timeout: float = 15.0) -> Any:
        req_id = secrets.token_hex(8)
        fut = asyncio.get_event_loop().create_future()
        self._pending[req_id] = fut

        await self.send_packet(kind, {"id": req_id, **payload}, op="req")

        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(req_id, None)
            raise ProtocolError(f"Request timeout for {kind}")

    async def abort(self, reason: str, code: str = AbortCode.INTERNAL_ERROR):
        await self.send_packet("abort", {"reason": reason, "code": code})
        self.state.phase = Phase.ABORTED
        raise ProtocolError(f"Aborted: {reason}")

    async def _handle_peer(self, from_role: ROLE, msg: Dict[str, Any]):
        if msg.get("type") != "packet":
            return

        payload = msg.get("payload", {})
        kind = payload.get("kind")
        seq = int(payload.get("seq", 0))
        op = payload.get("op", "req")

        if not self._validate_message_phase(kind):
            await self.abort(f"Message {kind} invalid in phase {self.state.phase}", AbortCode.PROTOCOL_VIOLATION)

        if op not in ("req", "resp"):
            await self.abort(f"Invalid op value: {op}", AbortCode.INVALID_MESSAGE)

        if kind == "profile_hello":
            conn_id = payload.get("conn_id")
            if conn_id and conn_id != self.state.peer_conn_id:
                self.state.peer_conn_id = conn_id
                self.state.peer_seq_in = 0

        if REQUIRE_SEQ_MONOTONIC and seq and seq <= self.state.peer_seq_in:
            self._out_of_order_count += 1
            if self._out_of_order_count % 5 == 0:
                self.logger.warning("many_out_of_order", role=self.role, count=self._out_of_order_count)
            return

        self.state.peer_seq_in = seq

        if self.state.transcript and kind in KINDS:
            self.state.transcript.record(from_role, kind, seq, payload)

        req_id = payload.get("rid")

        if op == "req" and kind in ["profile_hello", "pake_hello", "hs_hello"]:
            if not req_id:
                await self.abort(f"Request {kind} missing rid", AbortCode.INVALID_MESSAGE)
            await self._handle_request(kind, req_id, payload, from_role)
            return

        if op == "resp":
            if not req_id:
                await self.abort(f"Response {kind} missing rid", AbortCode.INVALID_MESSAGE)
            if req_id in self._pending:
                self._pending.pop(req_id).set_result(payload)
            else:
                self.logger.warning("unexpected_response", kind=kind, rid=req_id)
            return

        if kind == "pake_confirm":
            self.state.peer_pake_confirm = validate_base64(payload["tag_b64"], "pake_confirm", 32, 32)
        elif kind == "hs_auth":
            self.state.peer_hs_auth = validate_base64(payload["tag_b64"], "hs_auth", 32, 32)
        elif kind == "hs_confirm":
            self.state.peer_hs_confirm = validate_base64(payload["tag_b64"], "hs_confirm", 32, 32)
        elif kind == "secure_msg":
            await self._handle_secure(from_role, payload)
        elif kind == "abort":
            self.state.phase = Phase.ABORTED
            reason = payload.get("reason", "unknown")
            code = payload.get("code", AbortCode.INTERNAL_ERROR)
            raise ProtocolError(f"peer aborted ({code}): {reason}")

    async def _handle_request(self, kind: str, req_id: str, payload: Dict[str, Any], from_role: ROLE):
        inbox_entry = {
            "rid": req_id,
            "seq": payload.get("seq", 0),
            "kind": kind,
            "from_role": from_role,
            "body": {k: v for k, v in payload.items() if k not in ["rid", "op", "seq", "kind"]},
        }

        if kind in ["pake_hello", "hs_hello"]:
            self.state.inbox[kind].append(inbox_entry)

        response_payload: Dict[str, Any] = {}

        if kind == "profile_hello":
            response_payload = {"profiles": SUPPORTED_PROFILES, "min_profile": MIN_PROFILE, "conn_id": secrets.token_hex(8)}

        elif kind == "pake_hello":
            if self._pake_state:
                response_payload = {"msg_b64": b64e(self._pake_state["msg_out"])}
                if self.state.inbox["pake_hello"]:
                    self.state.inbox["pake_hello"].pop(0)
            else:
                self.logger.debug("deferred_pake_response", rid=req_id)
                return

        elif kind == "hs_hello":
            if self._hs_state:
                response_payload = {"pub_b64": b64e(self._hs_state["pub_raw"]), "nonce_b64": b64e(self._hs_state["nonce"])}
                if self.state.inbox["hs_hello"]:
                    self.state.inbox["hs_hello"].pop(0)
            else:
                self.logger.debug("deferred_hs_response", rid=req_id)
                return

        await self.send_packet(kind, {"id": req_id, **response_payload}, op="resp")

    async def _check_inbox(self, kind: str) -> Optional[Dict[str, Any]]:
        if self.state.inbox[kind]:
            entry = self.state.inbox[kind].pop(0)
            self.logger.debug("retrieved_from_inbox", kind=kind, rid=entry["rid"])
            return entry
        return None

    async def _handle_secure(self, from_role: ROLE, payload: Dict[str, Any]):
        if not self.state.recv_key or not self.state.th or not self.state.nonce_base_recv:
            return

        seq2 = int(payload.get("seq2", 0))
        if seq2 <= self.state.recv_seq2:
            self._out_of_order_count += 1
            return

        ct = validate_base64(payload["blob_b64"], "secure_ct", 17)

        aad = secure_aad(self.state.sid, self.state.profile, self.state.recon_th, self.state.th, from_role, seq2)
        nonce = build_nonce(self.state.nonce_base_recv, seq2)

        ChaCha20Poly1305 = require_aead()
        aead = ChaCha20Poly1305(self.state.recv_key)

        try:
            pt = aead.decrypt(nonce, ct, aad)
        except Exception as e:
            now_time = time.time()
            if now_time - self.state.last_decrypt_failure > 60:
                self.state.decrypt_failures = 0

            self.state.decrypt_failures += 1
            self.state.last_decrypt_failure = now_time

            if self.state.decrypt_failures >= MAX_DECRYPT_FAILURES:
                await self.abort(f"Too many decrypt failures ({self.state.decrypt_failures})", AbortCode.CRYPTO_ERROR)

            self.logger.warning("decryption_failed", role=self.role, error=str(e), failures=self.state.decrypt_failures)
            return

        self.state.decrypt_failures = 0
        self.state.recv_seq2 = seq2

        try:
            text = pt.decode("utf-8", errors="replace")
            print(f"[{self.role}] <- {from_role} ({seq2}): {text}")
        except Exception:
            print(f"[{self.role}] <- {from_role} ({seq2}): [binary, {len(pt)} bytes]")

    async def close(self):
        self._running = False
        if self._rx_task:
            self._rx_task.cancel()
            try:
                await self._rx_task
            except asyncio.CancelledError:
                pass

        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
            self.ws = None

        self.state.cleanup()

    async def run(self, demo_message: str = ""):
        try:
            await self.connect()

            self.state.phase = Phase.PROFILE_NEGOTIATING
            resp = await self.request("profile_hello", {
                "profiles": SUPPORTED_PROFILES,
                "min_profile": MIN_PROFILE,
                "conn_id": secrets.token_hex(8),
            })

            peer_profiles = resp.get("profiles", [])
            if not peer_profiles:
                await self.abort("No profiles supported by peer", AbortCode.PROFILE_MISMATCH)

            try:
                negotiated = negotiate_profile(SUPPORTED_PROFILES, peer_profiles)
            except ValueError:
                await self.abort("No mutually supported profile", AbortCode.PROFILE_MISMATCH)

            peer_min = resp.get("min_profile", MIN_PROFILE)
            if PROFILE_RANKS.get(negotiated, 0) < PROFILE_RANKS.get(peer_min, 0):
                await self.abort("Negotiated below peer minimum profile", AbortCode.PROFILE_DOWNGRADE)

            self.state.profile = negotiated
            self.state.transcript = Transcript(negotiated)
            self.state.recon_th = self.state.transcript.digest()

            self.state.phase = Phase.PAKE
            self._pake_state = pake_init(self.role, self.password, self.state.sid, negotiated)

            inbox_msg = await self._check_inbox("pake_hello")
            if inbox_msg:
                peer_msg_b64 = inbox_msg["body"].get("msg_b64")
                if not peer_msg_b64:
                    await self.abort("pake_hello missing msg_b64", AbortCode.INVALID_MESSAGE)
            else:
                resp = await self.request("pake_hello", {"msg_b64": b64e(self._pake_state["msg_out"])})
                peer_msg_b64 = resp.get("msg_b64")
                if not peer_msg_b64:
                    await self.abort("pake_hello response missing msg_b64", AbortCode.INVALID_MESSAGE)

            peer_msg = validate_base64(peer_msg_b64, "pake_msg", 16)

            try:
                self.state.k0 = pake_finish_reduced_timing(self._pake_state, peer_msg, self.state.sid, negotiated)
            except Exception:
                await self.abort("PAKE failed", AbortCode.AUTH_FAILED)

            self._pake_state = None
            self.state.phase = Phase.PAKE_DONE

            my_confirm = pake_confirm_tag(self.state.k0, self.state.sid, self.role, self.state.transcript.digest(), negotiated)
            await self.send_packet("pake_confirm", {"tag_b64": b64e(my_confirm)})

            for _ in range(100):
                if self.state.peer_pake_confirm is not None:
                    break
                await asyncio.sleep(0.1)
            if self.state.peer_pake_confirm is None:
                await self.abort("PAKE confirmation timeout", AbortCode.TIMEOUT)

            exp_peer = pake_confirm_tag(self.state.k0, self.state.sid, self.peer, self.state.transcript.digest(), negotiated)
            if not safe_compare(exp_peer, self.state.peer_pake_confirm, 32):
                await self.abort("PAKE confirm mismatch", AbortCode.AUTH_FAILED)

            print(f"SAS (compare out-of-band): {sas6(self.state.k0, self.state.sid, negotiated)}")

            self.state.phase = Phase.HANDSHAKING
            self._hs_state = hs_init(self.role, self.state.sid, negotiated, self.state.k0)

            inbox_msg = await self._check_inbox("hs_hello")
            if inbox_msg:
                peer_pub_b64 = inbox_msg["body"].get("pub_b64")
                peer_nonce_b64 = inbox_msg["body"].get("nonce_b64")
                if not peer_pub_b64 or not peer_nonce_b64:
                    await self.abort("hs_hello missing fields", AbortCode.INVALID_MESSAGE)
            else:
                resp = await self.request("hs_hello", {
                    "pub_b64": b64e(self._hs_state["pub_raw"]),
                    "nonce_b64": b64e(self._hs_state["nonce"]),
                })
                peer_pub_b64 = resp.get("pub_b64")
                peer_nonce_b64 = resp.get("nonce_b64")
                if not peer_pub_b64 or not peer_nonce_b64:
                    await self.abort("hs_hello response missing fields", AbortCode.INVALID_MESSAGE)

            peer_pub_raw = validate_base64(peer_pub_b64, "hs_pub", 32, 32)
            peer_nonce = validate_base64(peer_nonce_b64, "hs_nonce", 16, 16)

            derived = hs_derive_master(self._hs_state, peer_pub_raw, peer_nonce, self.state.recon_th)
            self.state.master = derived["master"]
            self.state.th = derived["th"]
            self.state.nonce_base_send = derived["nonce_base_send"]
            self.state.nonce_base_recv = derived["nonce_base_recv"]
            self._hs_state = None

            my_hs_tag = hs_auth_tag(self.state.master, self.role, self.state.th, negotiated)
            await self.send_packet("hs_auth", {"tag_b64": b64e(my_hs_tag)})

            for _ in range(100):
                if self.state.peer_hs_auth is not None:
                    break
                await asyncio.sleep(0.1)
            if self.state.peer_hs_auth is None:
                await self.abort("Handshake auth timeout", AbortCode.TIMEOUT)

            exp_peer_hs = hs_auth_tag(self.state.master, self.peer, self.state.th, negotiated)
            if not safe_compare(exp_peer_hs, self.state.peer_hs_auth, 32):
                await self.abort("Handshake auth mismatch", AbortCode.AUTH_FAILED)

            my_confirm_tag = hs_confirm_tag(derived["confirm_key"], self.role, self.state.th, negotiated)
            await self.send_packet("hs_confirm", {"tag_b64": b64e(my_confirm_tag)})

            for _ in range(100):
                if self.state.peer_hs_confirm is not None:
                    break
                await asyncio.sleep(0.1)
            if self.state.peer_hs_confirm is None:
                await self.abort("Key confirmation timeout", AbortCode.TIMEOUT)

            exp_peer_confirm = hs_confirm_tag(derived["confirm_key"], self.peer, self.state.th, negotiated)
            if not safe_compare(exp_peer_confirm, self.state.peer_hs_confirm, 32):
                await self.abort("Key confirmation mismatch", AbortCode.AUTH_FAILED)

            self.state.send_key, self.state.recv_key = derive_session_keys(self.state.master, self.state.th, self.role, negotiated)
            self.state.phase = Phase.ESTABLISHED

            self.logger.info("ESTABLISHED", role=self.role, profile=negotiated)

            if demo_message:
                await self.send_secure(demo_message)

            while self._running:
                try:
                    msg = await asyncio.wait_for(self._rx_queue.get(), timeout=1.0)
                    await self._process_received_message(msg)
                except asyncio.TimeoutError:
                    continue

        except ProtocolError as e:
            self.logger.error("protocol_error", role=self.role, error=str(e))
            raise
        except Exception as e:
            self.logger.error("unexpected_error", role=self.role, error=str(e))
            raise ProtocolError(f"Unexpected error: {e}")
        finally:
            await self.close()

    async def send_secure(self, text: str):
        if not self.state.send_key or not self.state.th or not self.state.nonce_base_send:
            raise ProtocolError("Not established")

        self.state.send_seq2 += 1
        seq2 = self.state.send_seq2

        nonce = build_nonce(self.state.nonce_base_send, seq2)
        aad = secure_aad(self.state.sid, self.state.profile, self.state.recon_th, self.state.th, self.role, seq2)

        ChaCha20Poly1305 = require_aead()
        aead = ChaCha20Poly1305(self.state.send_key)
        ct = aead.encrypt(nonce, text.encode("utf-8"), aad)

        await self.send_packet("secure_msg", {"seq2": seq2, "blob_b64": b64e(ct)})
        print(f"[{self.role}] -> {self.peer} ({seq2}): {text}")
