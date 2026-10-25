# AuthPulse — Project Documentation
### Cryptography and Network Security (CNS) Academic Presentation

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Cryptography Fundamentals](#2-cryptography-fundamentals)
3. [The 9-Step Message Authentication Protocol](#3-the-9-step-message-authentication-protocol)
4. [Replay Attacks and Message Tampering](#4-replay-attacks-and-message-tampering)
5. [Important Security Concepts and Limitations](#5-important-security-concepts-and-limitations)
6. [Project Architecture and Technologies](#6-project-architecture-and-technologies)
7. [Testing and Results](#7-testing-and-results)
8. [Viva Preparation](#8-viva-preparation)

---

## 1. Project Overview

### Problem Statement

Modern web APIs face two fundamental threats at the message level:

- **Message Tampering** — An attacker intercepts a request in transit and modifies the payload (e.g., changes a bank transfer amount) before the server receives it.
- **Replay Attacks** — An attacker captures a legitimately signed request and resends it later to repeat an action (e.g., initiating the same transfer twice).

Neither threat is prevented by simply using HTTPS alone if the application does not verify the integrity of its own messages, because TLS only protects data in transit — it does not bind a message to its sender or prevent resubmission.

### Objectives

AuthPulse demonstrates a complete, working message authentication system that:

1. **Proves integrity** — Any modification to a message after it is signed is detected by comparing HMAC tags.
2. **Proves authenticity** — Only a party holding the shared secret can produce a valid tag.
3. **Prevents replay attacks** — A signed message cannot be resent, because every nonce is stored and checked for uniqueness.
4. **Enforces freshness** — A signed message cannot be used outside a ±60-second window.

### How AuthPulse Addresses These Threats

AuthPulse implements a three-check sequential pipeline on every incoming request:

| Check | Threat Addressed | Mechanism |
|---|---|---|
| HMAC-SHA256 tag comparison | Tampering, forgery | `hmac.compare_digest` (constant-time) |
| Timestamp window (±60s) | Stale messages | `abs(now - timestamp) <= 60` |
| Nonce uniqueness | Replay attacks | SQLite UNIQUE constraint insert |

All three checks must pass for a message to be accepted. The order is deliberate: HMAC first (cheapest, catches tampering and forgery), timestamp second (catches stale messages), nonce third (requires a database write, only performed when the first two checks pass).

---

## 2. Cryptography Fundamentals

### 2.1 What Is a Hash Function?

A cryptographic hash function takes an input of any length and produces a fixed-length output called a **digest**. The key properties are:

- **Deterministic** — the same input always produces the same output.
- **One-way (pre-image resistance)** — you cannot reverse a digest back to the original input.
- **Collision-resistant** — it is computationally infeasible to find two different inputs that produce the same digest.
- **Avalanche effect** — changing even one bit of the input completely changes the output.

```
Input:  "hello"
SHA-256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

Input:  "hellp"  (one character changed)
SHA-256: f96c45756cc1bea8faa7d8862c89ed8f5c54c98d3ce98a75e3c97c09bed695b9
```

The two digests share no resemblance despite the inputs differing by one character. This is the avalanche effect.

### 2.2 SHA-256

SHA-256 is a member of the SHA-2 family of hash functions. It always produces a 256-bit (32-byte) digest, expressed as a 64-character hexadecimal string. It is standardised in FIPS 180-4 and is considered cryptographically secure.

SHA-256 alone is used for **integrity checking** (detecting accidental or deliberate changes to data), but it does not provide **authentication** because anyone can compute a SHA-256 hash of any message — there is no secret involved.

### 2.3 HMAC — Hash-based Message Authentication Code

HMAC (RFC 2104) combines a hash function with a **shared secret key** to produce a Message Authentication Code. The construction is:

```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
```

Where:
- `K` is the secret key
- `m` is the message
- `H` is a hash function (SHA-256 in AuthPulse)
- `opad` and `ipad` are fixed padding constants
- `||` denotes concatenation
- `⊕` denotes XOR

In practical terms, HMAC-SHA256 takes a message and a secret key and produces a 64-character hex tag. The same message and same key always produce the same tag. A different message **or** a different key produces a completely different tag.

```python
# AuthPulse implementation (app.py)
import hmac, hashlib

def compute_hmac(timestamp, nonce, payload):
    msg = signing_string(timestamp, nonce, payload).encode()
    return hmac.new(HMAC_SECRET.encode(), msg, hashlib.sha256).hexdigest()
```

### 2.4 What HMAC Provides

| Property | Provided by HMAC? | Explanation |
|---|---|---|
| **Integrity** | ✓ Yes | Any change to the message invalidates the tag |
| **Authentication** | ✓ Yes | Only parties with the secret key can produce a valid tag |
| **Non-repudiation** | ✗ No | Both parties hold the secret; either could have produced the tag |
| **Confidentiality (encryption)** | ✗ No | HMAC does not hide message content |
| **Replay prevention** | ✗ No (alone) | A captured tag is still valid on re-submission |

### 2.5 Hashing vs Encryption vs Digital Signatures vs HMAC

This is one of the most important distinctions in the subject:

| Mechanism | Key Required? | Reversible? | Purpose |
|---|---|---|---|
| **Hash (SHA-256)** | No | No (one-way) | Integrity check, fingerprinting |
| **Symmetric encryption (AES)** | Yes (shared) | Yes (decryptable) | Confidentiality |
| **Asymmetric encryption (RSA)** | Yes (public/private pair) | Yes (with private key) | Confidentiality, key exchange |
| **Digital signature (RSA/ECDSA)** | Yes (private key to sign, public to verify) | Not the message — but the signature is verifiable | Authentication, non-repudiation |
| **HMAC** | Yes (shared secret) | No — it is a MAC, not ciphertext | Integrity + Authentication together |

**AuthPulse uses HMAC, not encryption and not digital signatures.** The message payload is sent in plaintext. HMAC proves it was not modified and that the sender held the secret — but the content is readable by anyone who intercepts it. TLS/HTTPS provides the confidentiality layer in a real deployment.

### 2.6 Message Authentication Codes (MACs)

A MAC is a short piece of information attached to a message that allows the receiver to verify both the **integrity** (was the message changed?) and the **authenticity** (did it come from someone with the shared secret?). HMAC is the most widely used MAC construction in practice — it is used in TLS, JWT, SSH, and many payment APIs.

---

## 3. The 9-Step Message Authentication Protocol

AuthPulse implements the following nine-step protocol. Every step corresponds to an interactive stage in the Protocol Visualizer page.

### Overview Diagram

```
SENDER                                      RECEIVER
  │                                             │
  ├─ Step 1: Canonicalize payload               │
  ├─ Step 2: Build signing string               │
  ├─ Step 3: Compute HMAC-SHA256                │
  ├─ Step 4: Attach metadata ──────────────────►│
  │                                             ├─ Step 5: Recompute HMAC
  │                                             ├─ Step 6: Compare tags (HMAC check)
  │                                             ├─ Step 7: Check timestamp window
  │                                             ├─ Step 8: Check nonce uniqueness
  │                                             └─ Step 9: Accept or Reject
```

---

### Step 1 — Canonicalize the Payload

**Purpose:** Ensure that both the sender and receiver compute the HMAC over exactly the same byte sequence.

**The Problem:** JSON is not a canonical format. The same logical object can be serialized in multiple ways:

```json
{"amount": 100, "recipient": "alice"}      ← key order A
{"recipient": "alice", "amount": 100}      ← key order B (same data, different bytes)
```

If the sender and receiver serialize differently, they will compute different HMAC tags even for an unmodified message.

**The Solution:** Serialize with sorted keys and compact separators (no spaces):

```python
# AuthPulse implementation (app.py)
def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))
```

**Example:**
```
Input:  {"amount": 100, "recipient": "alice", "currency": "USD"}
Output: {"amount":100,"currency":"USD","recipient":"alice"}
```

Keys are alphabetically sorted, no spaces around `:` or `,`.

---

### Step 2 — Build the Signing String

**Purpose:** Combine all three security inputs — timestamp, nonce, and canonical payload — into one string that the HMAC will authenticate.

**Format:**
```
{timestamp}.{nonce}.{canonical_json}
```

**Example:**
```
1792860000.a8f21c9d3b44e7f1.{"amount":100,"currency":"USD","recipient":"alice"}
```

**Why include all three?**

| Component | What it protects against |
|---|---|
| Canonical payload | Tampering with message content |
| Timestamp | Stale message reuse |
| Nonce | Replay of the same message |

If only the payload were signed, an attacker could replay the same signed payload with a new timestamp and nonce, and the HMAC would still be valid. By including all three in the signing string, changing any of them invalidates the tag.

**AuthPulse Implementation:**
```python
def signing_string(timestamp: float, nonce: str, payload) -> str:
    return f"{timestamp}.{nonce}.{canonical_json(payload)}"
```

---

### Step 3 — Compute HMAC-SHA256

**Purpose:** Produce an authentication tag that can only be verified by someone who holds the same shared secret.

**Operation:**
```
tag = HMAC-SHA256(secret_key, signing_string)
```

**AuthPulse Implementation:**
```python
def compute_hmac(timestamp: float, nonce: str, payload) -> str:
    msg = signing_string(timestamp, nonce, payload).encode()
    return hmac.new(HMAC_SECRET.encode(), msg, hashlib.sha256).hexdigest()
```

**Example output (64-character hex):**
```
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
```

**Key security point:** The shared secret (`HMAC_SECRET`) is loaded from an environment variable (`.env` file). It never appears in the request payload, the database, the logs, or the frontend JavaScript. The receiver independently holds the same secret and uses it to recompute the expected tag.

---

### Step 4 — Attach Metadata and Transmit

**Purpose:** Assemble the complete request envelope and send it to the receiver.

**Request structure sent by sender:**
```json
{
  "payload": {"amount": 100, "recipient": "alice", "currency": "USD"},
  "timestamp": 1792860000.842,
  "nonce": "a8f21c9d3b44e7f1a8f21c9d3b44e7f1",
  "tag": "a1b2c3d4e5f6...64 hex chars..."
}
```

**What travels across the network:**
- The payload — **in plaintext**
- The timestamp — **in plaintext**
- The nonce — **in plaintext**
- The HMAC tag — **in plaintext**

**What does NOT travel:**
- The shared secret key — stays on both sides

This is the critical distinction between HMAC and encryption. An interceptor can read all four values in the request, but they cannot forge a valid tag for a modified payload without the secret key.

---

### Step 5 — Recompute the HMAC at the Receiver

**Purpose:** Independently verify the received message without trusting the sender-supplied tag.

The receiver takes the received `payload`, `timestamp`, and `nonce`, constructs the same signing string, and computes its own HMAC using its copy of the shared secret:

```
expected_tag = HMAC-SHA256(secret_key, f"{timestamp}.{nonce}.{canonical_json(payload)}")
```

If the payload was modified in transit, `canonical_json(modified_payload)` differs from `canonical_json(original_payload)`, so the expected tag will be different from the received tag.

---

### Step 6 — Compare Tags (Tamper Detection)

**Purpose:** Determine whether the received tag matches the independently computed tag.

**AuthPulse Implementation:**
```python
expected_tag = compute_hmac(timestamp, nonce, payload)
tags_match = hmac.compare_digest(expected_tag, str(tag))
```

**Why `hmac.compare_digest` instead of `==`?**

A regular string comparison (`==`) short-circuits: it returns `False` as soon as the first differing character is found. This means comparisons for very similar tags take slightly longer than comparisons for completely different tags.

A **timing attack** exploits this: an attacker submits thousands of guessed tags and measures response times to infer correct characters one by one. `hmac.compare_digest` compares every character in constant time regardless of where the first mismatch occurs, making timing attacks infeasible.

**Outcome:**
- Tags match → proceed to Step 7
- Tags do not match → reject immediately with reason `tamper`; Steps 7 and 8 are not executed

---

### Step 7 — Check Timestamp Freshness

**Purpose:** Reject messages that are too old or arrive with a future timestamp.

**AuthPulse Implementation:**
```python
TIMESTAMP_WINDOW_SECONDS = 60

now = time.time()
age = now - timestamp
within_window = abs(age) <= TIMESTAMP_WINDOW_SECONDS
```

**Logic:**
```
If |server_time - request_timestamp| <= 60 seconds → PASS
Otherwise → FAIL (reason: "expired")
```

**Example:**
```
Server time:      1792860100
Request timestamp: 1792860000
Age:              100 seconds
Result:           FAIL — outside ±60s window
```

**Why this check alone is not enough against replay:** If an attacker captures a signed message and resends it within 60 seconds, this check will pass. The nonce check in Step 8 is what actually prevents replay.

**Outcome:**
- Within window → proceed to Step 8
- Outside window → reject with reason `expired`

---

### Step 8 — Check Nonce Uniqueness (Replay Prevention)

**Purpose:** Ensure each signed message can only be accepted once, even if the HMAC is valid and the timestamp is fresh.

A **nonce** (Number Used Once) is a random value included in the request. AuthPulse generates a 32-character cryptographically random hex nonce for each message using Python's `secrets.token_hex(16)`.

**AuthPulse Implementation:**
```python
conn.execute("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)",
             (nonce, _iso_now()))
```

The `nonces` table has a `PRIMARY KEY` constraint on the nonce column. An `INSERT` of a duplicate nonce raises `sqlite3.IntegrityError`, which is caught and treated as a replay.

**Why a database constraint?**

The constraint is enforced at the database level, not in application code. This means two concurrent requests with the same nonce cannot both succeed — the database's transaction isolation ensures exactly one INSERT succeeds and the other raises an integrity error. This handles the race condition that would exist if the uniqueness check were done in application code (read-then-write).

**Outcome:**
- Nonce not seen before → INSERT succeeds → ACCEPTED (reason: `ok`)
- Nonce already used → INSERT fails → REJECTED (reason: `replay`)

---

### Step 9 — Accept or Reject

**Purpose:** Combine all check results into the final security decision.

**Accept conditions (all three must be true):**
1. HMAC tag matches (integrity + authenticity confirmed)
2. Timestamp within ±60 seconds (freshness confirmed)
3. Nonce has not been seen before (uniqueness confirmed)

**Final decision table:**

| HMAC | Timestamp | Nonce | Decision | Reason |
|---|---|---|---|---|
| ✓ | ✓ | ✓ | ACCEPTED | ok |
| ✗ | — | — | REJECTED | tamper |
| ✓ | ✗ | — | REJECTED | expired |
| ✓ | ✓ | ✗ | REJECTED | replay |

**Important:** AuthPulse short-circuits at the first failing check. If HMAC fails, the timestamp and nonce checks are never evaluated. This means the response for a tampered message contains only one check trace entry, not three. This is intentional — it avoids leaking information about whether a forged message's timestamp or nonce would have been valid.

**The nonce is only stored after HMAC and timestamp checks pass.** This is deliberate: if a malicious actor floods the server with invalid requests, they cannot exhaust the nonce store, because only requests with valid HMACs reach the nonce check.

---

## 4. Replay Attacks and Message Tampering

### 4.1 Message Tampering

**Definition:** An attacker intercepts a legitimate request and modifies the payload before it reaches the server, while keeping the original HMAC tag.

**How it works:**

```
Original request (signed by sender):
  payload: {"amount": 100, "recipient": "alice"}
  tag:      HMAC(secret, "1792860000.nonce.{\"amount\":100,\"recipient\":\"alice\"}")

Attacker modifies the payload:
  payload: {"amount": 99999, "recipient": "attacker"}
  tag:      (same original tag — attacker does not have the secret to recompute it)

Receiver recomputes:
  expected_tag = HMAC(secret, "1792860000.nonce.{\"amount\":99999,\"recipient\":\"attacker\"}")
  ≠ original tag → REJECTED (reason: tamper)
```

**Why it fails:** The attacker cannot compute a valid HMAC for the modified payload because they do not hold the shared secret. Even changing one character in the payload changes the canonical JSON, which changes the signing string, which changes the HMAC output completely (avalanche effect).

**AuthPulse simulation (`/api/simulate/tamper`):** Signs a payload, increments the first numeric field by one, then submits the modified payload with the original tag. The HMAC check always fails.

---

### 4.2 Replay Attacks

**Definition:** An attacker captures a complete, validly signed request (all four fields intact: payload, timestamp, nonce, tag) and resends it to repeat the action.

**Why the HMAC check does not help:**

```
Original request (accepted):
  payload:   {"action": "transfer", "amount": 500}
  timestamp: 1792860000
  nonce:     a8f21c...
  tag:       (valid HMAC computed over all three)

Replay (within 60 seconds):
  (same payload, timestamp, nonce, tag — nothing changed)

Receiver checks:
  HMAC:      PASS (tag is still valid — nothing was tampered)
  Timestamp: PASS (still within 60 seconds)
  Nonce:     FAIL (a8f21c... already in the nonces table)
  → REJECTED (reason: replay)
```

**The key teaching point:** A valid HMAC proves the message was authentic when it was sent. It does not prove the message is being sent for the first time. That is why nonce uniqueness is a separate, independent mechanism.

**AuthPulse simulation (`/api/simulate/replay`):** Signs a payload, submits it once (accepted), then submits the identical request again. The second attempt returns `rejected / replay`. The HMAC and timestamp checks still pass on the second attempt — only the nonce check fails.

---

### 4.3 Why Both Mechanisms Are Needed Together

| Attack | Stopped by HMAC alone? | Stopped by timestamp alone? | Stopped by nonce alone? | Stopped by HMAC + timestamp + nonce? |
|---|---|---|---|---|
| Payload tampering | ✓ Yes | ✗ No | ✗ No | ✓ Yes |
| Replay within window | ✗ No | ✗ No | ✓ Yes | ✓ Yes |
| Replay outside window | ✗ No | ✓ Yes | ✓ Yes | ✓ Yes |
| Tag forgery (no secret) | ✓ Yes | — | — | ✓ Yes |

---

## 5. Important Security Concepts and Limitations

### 5.1 Why HMAC Alone Cannot Prevent Replay Attacks

HMAC verifies that a message was produced by someone with the shared secret and has not been altered. It says nothing about **how many times** the message has been submitted. A replay is a legitimate message submitted again — the HMAC is valid because nothing changed.

Nonce uniqueness is the mechanism that adds the "once" semantics: each nonce is consumed on first use.

### 5.2 Why Timestamps Alone Are Insufficient

A timestamp window only rejects messages older than 60 seconds. An attacker who captures a valid request can replay it within that 60-second window, and the timestamp check will pass. The nonce check is required to prevent this.

The timestamp window does serve a useful secondary purpose: it prevents accumulation of old nonces in the database. In a production system, nonces older than the window can be purged safely, because any request old enough to use them would fail the timestamp check before reaching the nonce check.

### 5.3 HMAC Does Not Encrypt the Payload

The payload in an AuthPulse request is transmitted **in plaintext**. Anyone who can observe the network traffic can read the payload contents. HMAC ensures the payload was not **modified**, not that it is **secret**.

```
Request on the wire (readable by anyone):
{
  "payload": {"amount": 100, "recipient": "alice"},   ← visible
  "timestamp": 1792860000,                              ← visible
  "nonce": "a8f21c...",                                 ← visible
  "tag": "a1b2c3..."                                    ← visible (but unforgeable)
}
```

For confidentiality in a real deployment, TLS/HTTPS encrypts the entire HTTP request body, including the HMAC-protected payload. AuthPulse does not implement encryption at the application layer because it is a demonstration of message authentication, not encryption.

### 5.4 Why HTTPS/TLS Is Needed in Practice

| Protection | HMAC provides? | TLS provides? |
|---|---|---|
| Integrity (tamper detection) | ✓ Yes | ✓ Yes |
| Authentication (sender verification) | ✓ Yes (shared secret) | ✓ Yes (certificates) |
| Confidentiality (eavesdropping prevention) | ✗ No | ✓ Yes |
| Replay prevention | Only with nonce | Not alone |

HMAC and TLS are **complementary**: TLS encrypts the channel (preventing eavesdropping), while HMAC authenticates the message (preventing tampering and replay even if TLS were somehow bypassed or if the attacker had access to application logs).

### 5.5 Shared Secret Management

The strength of HMAC-SHA256 depends entirely on the secrecy of the shared key. In AuthPulse:

- The secret is stored in a `.env` file excluded from version control
- It is loaded as an environment variable at startup
- It never appears in the database, logs, API responses, or frontend code
- In production, it should be rotated periodically and stored in a secrets manager

If the shared secret is leaked, an attacker can forge valid HMAC tags for arbitrary payloads, bypassing the integrity check entirely.

### 5.6 Nonce Storage Security

The `nonces` table must be persistent (survives server restarts) and atomic (concurrent inserts of the same nonce must only succeed once). AuthPulse uses SQLite with a `PRIMARY KEY` constraint and WAL (Write-Ahead Logging) mode, which satisfies both requirements for a single-server deployment.

In a distributed system (multiple servers), the nonce store must be shared across all instances — a per-process in-memory store is insufficient because two different servers could independently accept the same nonce.

---

## 6. Project Architecture and Technologies

### File Structure

```
authpulse/
├── app.py                        Backend: Flask + crypto pipeline
├── .env                          HMAC secret (gitignored)
├── .env.example                  Template for secret config
├── requirements.txt              Python dependencies
├── tests/
│   ├── conftest.py               Test isolation (per-test SQLite DB)
│   ├── test_verify.py            12 pipeline tests
│   └── test_error.py             2 error-handling tests
└── static/
    ├── index.html                Single-page app shell
    ├── css/style.css             Design system
    └── js/
        ├── app.js                Entry point (ES module)
        ├── core.js               Shared state, api(), utilities
        ├── router.js             Page navigation
        ├── overview.js           Dashboard page
        ├── lab.js                Message Lab page
        ├── simulator.js          Attack Simulator page
        ├── logs.js               Verification Logs page
        ├── playground.js         API Playground page
        ├── visualizer.js         Protocol Visualizer page
        └── howItWorks.js         Reference page
```

### Technology Stack

| Component | Technology | Reason |
|---|---|---|
| Backend | Python 3.11, Flask 3.0 | Lightweight, exposes `hmac` and `hashlib` directly |
| Cryptography | Python stdlib `hmac`, `hashlib` | Standard library — no third-party crypto dependency |
| Database | SQLite (WAL mode) | Simple, zero-config, atomic UNIQUE constraints |
| Frontend | Plain HTML/CSS/ES Modules | No build step — every line is visible and auditable |
| Secret management | `python-dotenv`, env vars | Secret never reaches the frontend |

The entire cryptographic implementation is in Python's standard library `hmac` and `hashlib` modules — no external crypto library is used, making the implementation fully auditable.

---

## 7. Testing and Results

All test results below are from actual test runs on the implemented code. Nothing has been fabricated.

### 7.1 Test Suite Overview

```
14 tests collected. 14 passed.

tests/test_error.py::test_400_returns_json       PASSED
tests/test_error.py::test_500_returns_json       PASSED
tests/test_verify.py::test_valid_request_accepted        PASSED
tests/test_verify.py::test_tampered_payload_rejected     PASSED
tests/test_verify.py::test_expired_request_rejected      PASSED
tests/test_verify.py::test_replay_rejected               PASSED
tests/test_verify.py::test_concurrent_duplicate_replay   PASSED
tests/test_verify.py::test_sign_endpoint                 PASSED
tests/test_verify.py::test_simulate_tamper               PASSED
tests/test_verify.py::test_simulate_replay               PASSED
tests/test_verify.py::test_simulate_expired              PASSED
tests/test_verify.py::test_events_pagination             PASSED
tests/test_verify.py::test_stats                         PASSED
tests/test_verify.py::test_health                        PASSED
```

### 7.2 Scenario: Valid Message

**Setup:** Payload is signed server-side using `/api/sign`. The returned timestamp, nonce, and tag are submitted unchanged to `/api/verify`.

**Expected result:** `accepted / ok` — all three checks pass.

**Actual result:**
```json
{
  "result": "accepted",
  "reason": "ok",
  "checks": [
    {"name": "hmac",      "status": "pass", "detail": "Computed tag matches supplied tag."},
    {"name": "timestamp", "status": "pass", "detail": "Message age 0.2s – within ±60s window."},
    {"name": "nonce",     "status": "pass", "detail": "Nonce is unique – first time seen."}
  ]
}
```

### 7.3 Scenario: Tampered Message

**Setup:** Payload is signed correctly. Before submitting to `/api/verify`, the `amount` field is changed from 100 to 99999. The original tag (computed over the unmodified payload) is kept.

**Expected result:** `rejected / tamper` — HMAC check fails. Timestamp and nonce checks are not reached.

**Actual result:**
```json
{
  "result": "rejected",
  "reason": "tamper",
  "checks": [
    {
      "name": "hmac",
      "status": "fail",
      "detail": "Computed tag does NOT match – payload may have been tampered with.",
      "expected": "c47033890bd2332f...",
      "received": "352067e9eb84f3a6..."
    }
  ]
}
```

Only one check is returned — the pipeline short-circuits after the first failure.

### 7.4 Scenario: Replay Attack

**Setup:** A valid signed message is submitted twice, unchanged.

**Expected result:**
- First submission: `accepted / ok`
- Second submission: `rejected / replay` — HMAC and timestamp checks pass, nonce check fails

**Actual result:**
```
First:  accepted / ok    — checks: [pass, pass, pass]
Second: rejected / replay — checks: [pass, pass, fail]
```

This demonstrates the critical teaching point: a replayed request has a valid HMAC and a valid timestamp. Only the nonce check stops it.

### 7.5 Scenario: Expired Timestamp

**Setup:** Payload is signed with a timestamp 120 seconds in the past. The signing is correct (HMAC is valid for the old timestamp).

**Expected result:** `rejected / expired` — HMAC check passes, timestamp check fails.

**Actual result:**
```json
{
  "result": "rejected",
  "reason": "expired",
  "checks": [
    {"name": "hmac",      "status": "pass", "detail": "Computed tag matches supplied tag."},
    {"name": "timestamp", "status": "fail", "detail": "Message age 120.3s – outside ±60s window."}
  ]
}
```

This demonstrates that a correctly signed but stale message is still rejected — and that HMAC validity does not imply freshness.

### 7.6 Scenario: Concurrent Duplicate Replay

**Setup:** Two threads simultaneously submit the same signed message to `/api/verify`.

**Expected result:** Exactly one `accepted`, exactly one `rejected / replay` — the database UNIQUE constraint ensures atomicity.

**Actual result:** One accepted, one rejected — confirmed by `test_concurrent_duplicate_replay` passing consistently.

---

## 8. Viva Preparation

### 8.1 Fundamental Cryptography

**Q: What is the difference between hashing and encryption?**

Hashing is a one-way function — you cannot recover the original input from the hash output. Encryption is two-way — the ciphertext can be decrypted back to plaintext using the appropriate key. SHA-256 is a hash function; AES is a symmetric encryption algorithm. AuthPulse uses hashing (via HMAC), not encryption.

**Q: What is an HMAC and how does it differ from a plain hash?**

A plain hash has no secret key — anyone can compute `SHA-256("hello")`. An HMAC takes both a message and a secret key. Without the key, you cannot compute the correct HMAC. This gives HMAC both integrity (the message was not changed) and authentication (the sender held the secret). SHA-256 alone only provides integrity.

**Q: Why is hmac.compare_digest used instead of == for tag comparison?**

A regular `==` comparison is vulnerable to timing attacks: it returns False as soon as it finds the first differing character, so comparisons of "closer" guesses take slightly longer. An attacker can measure these timing differences to guess the correct tag one character at a time. `hmac.compare_digest` compares every character in constant time regardless of where the first mismatch is, eliminating the timing side-channel.

**Q: What is the avalanche effect and why is it important?**

The avalanche effect means that a tiny change to the input produces a completely different hash output. Changing one character in a 1000-byte JSON payload changes all 64 hex characters of the SHA-256 output. This means an attacker cannot make "small" modifications to a payload and hope the HMAC changes only slightly — it changes completely and is detected immediately.

**Q: What is a nonce and why must it be random?**

A nonce (Number Used Once) is a unique identifier for each request. It must be random so an attacker cannot predict future nonces, and it must be used only once so a captured request cannot be replayed. AuthPulse generates nonces using Python's `secrets.token_hex(16)`, which produces 128 bits of cryptographically random data.

**Q: Does AuthPulse provide non-repudiation?**

No. Non-repudiation requires asymmetric cryptography (digital signatures). With a digital signature, only the holder of the private key can sign, but anyone with the public key can verify — so the signer cannot deny having signed. HMAC uses a shared secret, meaning both the sender and receiver can produce a valid tag. Either party could have generated it, so HMAC cannot prove which party produced it.

---

### 8.2 Protocol Design Decisions

**Q: Why is the check order HMAC → timestamp → nonce, and not a different order?**

The order is chosen by cost and fail-fast efficiency:

1. **HMAC first** — cheapest operation (just a hash computation), catches the most attacks (tampering and forgery), requires no database access. Most malicious requests will fail here.
2. **Timestamp second** — cheap (just an arithmetic comparison), eliminates stale messages before a database write is needed.
3. **Nonce third** — most expensive (requires a database write). By doing this last, the database is only written to for requests that passed the first two checks. This prevents attackers from exhausting the nonce store with flood attacks.

**Q: Why is the nonce only stored after the first two checks pass?**

If the nonce were stored before the HMAC check, an attacker could flood the server with invalid requests to fill the nonce database with garbage values. By writing the nonce only after HMAC and timestamp pass, malicious traffic is filtered cheaply before it ever touches the database.

**Q: Why does the signing string include timestamp and nonce, not just the payload?**

If only the payload were signed, the HMAC tag would be the same for every request with the same payload. An attacker who captured one valid `{"amount":100}` request could replay it forever with a fresh timestamp and nonce, and the HMAC would still be valid. Including timestamp and nonce in the signing string binds each tag to one specific request — changing either invalidates the tag.

**Q: What happens if the shared secret is compromised?**

An attacker who obtains the shared secret can compute valid HMAC tags for any payload they choose, bypass the HMAC check entirely, and the system provides no protection. This is a fundamental property of shared-secret systems. The secret must be rotated immediately if compromised, and all outstanding nonces should be invalidated. In production, use a dedicated secrets manager (AWS Secrets Manager, HashiCorp Vault) rather than a `.env` file.

**Q: Why does the receiver perform canonicalization again instead of trusting the sender's canonical JSON?**

The receiver cannot trust the sender to have canonicalized correctly, because the HMAC is computed over the canonical JSON. If the receiver serializes differently from the sender, the expected tag would differ even for a legitimate message. Both sides must use the same deterministic serialization.

More importantly: both sides compute the canonical JSON independently from the received `payload` object. This ensures that what is authenticated is the logical content of the payload, not the byte sequence chosen by the sender.

**Q: Can the system scale to multiple servers?**

In its current form, the SQLite nonce database is local to one server. If two servers both accept a replay (because each only knows about its own nonce store), the replay protection is broken. For horizontal scaling, the nonce store must be shared — for example, using Redis with an atomic `SET NX` operation or a distributed SQL database with proper transaction isolation.

---

### 8.3 Comparing AuthPulse to Real Systems

**Q: How is this similar to how payment APIs like Stripe authenticate requests?**

Stripe's webhook authentication uses HMAC-SHA256 with a shared signing secret, a timestamp to prevent replay, and expects requests within a ±300-second window — exactly the same three-layer approach as AuthPulse. AuthPulse's architecture is directly inspired by production API authentication patterns.

**Q: How does this compare to JWT (JSON Web Tokens)?**

JWT typically uses either HMAC-SHA256 (HS256) or RSA signatures (RS256) to sign a payload. The structure is similar: a header, payload, and signature. AuthPulse differs in that it adds explicit nonce tracking for replay prevention — JWTs typically rely only on expiry (`exp` claim) and do not track individual token IDs unless the application adds a token blocklist.

**Q: Why use HMAC rather than a digital signature (RSA/ECDSA)?**

Digital signatures require asymmetric key infrastructure (public/private key pairs, certificate management). HMAC requires only a shared secret, which is simpler to implement and faster to compute. For server-to-server communication where both parties are known and trusted, HMAC is the standard choice. For client-to-server communication where the client should not hold a server secret (e.g., user authentication), digital signatures or token-based schemes are more appropriate.

---

*This documentation was prepared from the actual AuthPulse source code. All test results are from real test runs. All code excerpts are from the live implementation.*
