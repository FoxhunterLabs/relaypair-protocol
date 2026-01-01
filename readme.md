________________________________________
# RelayPair Protocol

**RelayPair** is a relay-agnostic, human-mediated secure pairing protocol.

It allows two peers (“alice” and “bob”) to establish authenticated session keys over an
**untrusted relay** using a short shared secret (PIN or high-entropy secret), without
relying on PKI, certificates, or trusted infrastructure.

This repository contains a **reference implementation** of the protocol, intended for
inspection, experimentation, and integration as a building block — not as a turnkey product.

---

## What problem this solves

Securely pairing two endpoints is deceptively hard when:

- The network is hostile or untrusted
- A relay may observe, modify, replay, or drop messages
- No prior trust or PKI exists
- Humans must remain the final authority

RelayPair is designed for situations where **pairing correctness matters more than convenience**:
industrial systems, field devices, recovery channels, temporary links, and human-in-the-loop workflows.

---

## Design goals

- **Relay agnostic**  
  The relay is treated as malicious by default.

- **Human-mediated trust**  
  Users verify a short authentication string (SAS) out-of-band.

- **Deterministic, auditable flow**  
  Explicit protocol phases, transcripts, and abort conditions.

- **Minimal surface area**  
  No background services, no identity infrastructure, no long-lived keys.

- **Fail closed**  
  Any ambiguity, downgrade, or cryptographic failure aborts the protocol.

---

## Non-goals

RelayPair explicitly does **not** attempt to provide:

- Metadata privacy
- Deniability
- Post-compromise security
- Resistance to endpoint compromise
- General-purpose messaging or transport features

Those concerns are intentionally left to higher-level systems.

---

## Threat model (summary)

Assumes an adversary who can:

- Fully control the relay (MITM, replay, reorder, inject, drop)
- Observe all network traffic
- Attempt protocol downgrade or confusion
- Attempt online guessing attacks

Assumes users can:

- Share a short secret (PIN) or high-entropy secret
- Compare a short SAS out-of-band

If the protocol completes successfully, both peers share authenticated session keys and
can exchange AEAD-protected messages.

---

## Cryptographic building blocks

- **SPAKE2** — Password-Authenticated Key Exchange  
- **X25519** — Ephemeral Diffie-Hellman  
- **HKDF-SHA256** — Key derivation  
- **ChaCha20-Poly1305** — Authenticated encryption  

All keys are ephemeral and scoped to a single session.

---

## Repository structure

relaypair_protocol/
src/relaypair/
core/ # crypto, validation, transcripts, invariants
protocol/ # client state machine and protocol logic
relay/ # untrusted WebSocket relay
cli.py # reference CLI

The protocol logic is intentionally separated from transport and relay behavior.

---

## Installation

```bash
pip install -e .
Python 3.9+ required.
________________________________________
Quick start
1) Start the untrusted relay
relaypair relay --host 127.0.0.1 --port 8000
2) Create a session
curl -X POST http://127.0.0.1:8000/session
Note the returned session_code.
3) Run both peers
relaypair client --url ws://127.0.0.1:8000 --session ABCD1234 --role alice --pin 123456
relaypair client --url ws://127.0.0.1:8000 --session ABCD1234 --role bob   --pin 123456
Compare the SAS shown on both sides before continuing.
________________________________________
Protocol guarantees
If pairing completes successfully:
•	Both peers agree on the protocol profile and version
•	A PAKE prevents offline guessing of the shared secret
•	Session keys are authenticated to the shared secret
•	All application data is AEAD-protected
•	Replay and reordering are detected and rejected
If any step fails, the protocol aborts without partial success.
________________________________________
Abort conditions (non-exhaustive)
The protocol aborts on:
•	Profile or version downgrade
•	Transcript mismatch
•	Authentication tag mismatch
•	Unexpected message ordering
•	Excessive decryption failures
•	Timeouts at critical phases
Abort behavior is explicit and intentional.
________________________________________
Security status
⚠️ This is a reference implementation.
•	Not formally verified
•	Not audited
•	Not hardened for production use
It is intended to demonstrate protocol structure, invariants, and failure handling —
not to serve as drop-in production cryptography.
________________________________________
Intended use
RelayPair is suitable as:
•	A pairing primitive inside larger systems
•	A reference design for human-mediated pairing
•	A testbed for relay-hostile protocol design
It is not a messaging app, identity system, or general secure transport.
________________________________________
License
MIT
