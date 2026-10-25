"""
AuthPulse backend – Flask + SQLite demonstration of HMAC-SHA256
message authentication, tamper detection, and replay prevention.
"""

import json
import hmac
import hashlib
import sqlite3
import secrets as _secrets
import time
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("AUTHPULSE_DB_PATH", BASE_DIR / "authpulse.db"))
STATIC_DIR = BASE_DIR / "static"

HMAC_SECRET = os.environ.get("AUTHPULSE_SECRET", "super-secret-key-change-me-in-production")
TIMESTAMP_WINDOW_SECONDS = 60

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder=None)
app.config["JSON_SORT_KEYS"] = False


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    """Return a SQLite connection in WAL mode with row-factory."""
    conn = sqlite3.connect(str(DB_PATH), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id    TEXT NOT NULL,
            payload       TEXT NOT NULL,
            timestamp     REAL NOT NULL,
            nonce         TEXT NOT NULL,
            tag           TEXT NOT NULL,
            result        TEXT NOT NULL,            -- accepted | rejected
            reason        TEXT,                     -- short reason phrase
            checks_json   TEXT NOT NULL,            -- JSON array of check traces
            created_at    TEXT NOT NULL             -- ISO 8601 UTC
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_result ON events(result)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_request ON events(request_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            nonce       TEXT PRIMARY KEY,
            created_at  TEXT NOT NULL
        )
    """)
    conn.close()


# Initialize database on import so tables exist in all contexts
# (including Flask's debug reloader child process).
init_db()


# ---------------------------------------------------------------------------
# Core crypto / verification pipeline
# ---------------------------------------------------------------------------

def canonical_json(obj) -> str:
    """Return compact JSON with sorted keys – used as the signing string."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def signing_string(timestamp: float, nonce: str, payload) -> str:
    """Build the canonical string: '{timestamp}.{nonce}.{canonical_json}'."""
    return f"{timestamp}.{nonce}.{canonical_json(payload)}"


def compute_hmac(timestamp: float, nonce: str, payload) -> str:
    msg = signing_string(timestamp, nonce, payload).encode()
    return hmac.new(HMAC_SECRET.encode(), msg, hashlib.sha256).hexdigest()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_verification(payload, timestamp, nonce, tag, request_id=None) -> dict:
    """
    Execute the full verification pipeline and persist an event row.

    Check order:
      1. HMAC equality (fail → tampering)
      2. Timestamp window (fail → expired)
      3. Nonce uniqueness (fail → replay)

    Returns a dict with result, reason, and a per-check trace list.
    """
    checks = []

    # --- Check 1: HMAC ---------------------------------------------------
    expected_tag = compute_hmac(timestamp, nonce, payload)
    tags_match = hmac.compare_digest(expected_tag, str(tag))
    checks.append({
        "name": "hmac",
        "label": "HMAC-SHA256 Integrity",
        "status": "pass" if tags_match else "fail",
        "detail": "Computed tag matches supplied tag." if tags_match
                  else "Computed tag does NOT match – payload may have been tampered with.",
        "expected": expected_tag,
        "received": str(tag),
    })

    if not tags_match:
        reason = "tamper"
        _persist_event(request_id, payload, timestamp, nonce, tag,
                        "rejected", reason, checks)
        return {"result": "rejected", "reason": reason, "checks": checks}

    # --- Check 2: Timestamp window --------------------------------------
    now = time.time()
    age = now - timestamp
    within_window = abs(age) <= TIMESTAMP_WINDOW_SECONDS
    checks.append({
        "name": "timestamp",
        "label": "Timestamp Window (60s)",
        "status": "pass" if within_window else "fail",
        "detail": f"Message age {age:.1f}s – within ±{TIMESTAMP_WINDOW_SECONDS}s window." if within_window
                  else f"Message age {age:.1f}s – outside ±{TIMESTAMP_WINDOW_SECONDS}s window.",
        "age_seconds": round(age, 2),
        "window_seconds": TIMESTAMP_WINDOW_SECONDS,
    })

    if not within_window:
        reason = "expired"
        _persist_event(request_id, payload, timestamp, nonce, tag,
                        "rejected", reason, checks)
        return {"result": "rejected", "reason": reason, "checks": checks}

    # --- Check 3: Nonce uniqueness (replay prevention) -------------------
    conn = get_db()
    try:
        conn.execute("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)",
                     (nonce, _iso_now()))
        nonce_unique = True
    except sqlite3.IntegrityError:
        nonce_unique = False
    finally:
        conn.close()

    checks.append({
        "name": "nonce",
        "label": "Nonce Uniqueness",
        "status": "pass" if nonce_unique else "fail",
        "detail": "Nonce is unique – first time seen." if nonce_unique
                  else "Nonce already used – replay attempt detected.",
        "nonce": nonce,
    })

    reason = "ok" if nonce_unique else "replay"
    result = "accepted" if nonce_unique else "rejected"

    _persist_event(request_id, payload, timestamp, nonce, tag,
                    result, reason, checks)
    return {"result": result, "reason": reason, "checks": checks}


def _persist_event(request_id, payload, timestamp, nonce, tag,
                    result, reason, checks):
    if request_id is None:
        request_id = _secrets.token_hex(8)
    conn = get_db()
    conn.execute("""
        INSERT INTO events
            (request_id, payload, timestamp, nonce, tag, result,
             reason, checks_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        request_id,
        canonical_json(payload),
        timestamp,
        nonce,
        str(tag),
        result,
        reason,
        json.dumps(checks),
        _iso_now(),
    ))
    conn.close()


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.post("/api/sign")
def api_sign():
    """Demo client endpoint: signs a payload server-side and returns the tag.

    Optional body fields:
      timestamp   float  – override the timestamp (for expired simulation)
      nonce       str    – override the nonce (for replay simulation)
    """
    data = request.get_json(force=True, silent=True)
    if not data or "payload" not in data:
        return jsonify({"error": "Missing 'payload' in request body."}), 400

    payload = data["payload"]
    timestamp = float(data["timestamp"]) if "timestamp" in data else time.time()
    nonce = str(data["nonce"]) if "nonce" in data else _secrets.token_hex(16)
    tag = compute_hmac(timestamp, nonce, payload)

    return jsonify({
        "request_id": _secrets.token_hex(8),
        "payload": payload,
        "timestamp": timestamp,
        "nonce": nonce,
        "tag": tag,
        "signing_string": signing_string(timestamp, nonce, payload),
    })


@app.post("/api/verify")
def api_verify():
    """Verify an incoming signed message against the 3-check pipeline."""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body."}), 400

    required = ["payload", "timestamp", "nonce", "tag"]
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    request_id = data.get("request_id") or _secrets.token_hex(8)
    payload = data["payload"]
    timestamp = float(data["timestamp"])
    nonce = str(data["nonce"])
    tag = str(data["tag"])

    outcome = run_verification(payload, timestamp, nonce, tag, request_id)
    return jsonify({
        "request_id": request_id,
        "result": outcome["result"],
        "reason": outcome["reason"],
        "checks": outcome["checks"],
    })


@app.post("/api/simulate/tamper")
def api_sim_tamper():
    """Sign a payload, then flip a value before verifying."""
    data = request.get_json(force=True, silent=True) or {}
    payload = data.get("payload", {"amount": 100, "recipient": "alice"})
    timestamp = time.time()
    nonce = _secrets.token_hex(16)
    tag = compute_hmac(timestamp, nonce, payload)

    # Tamper: modify payload in place
    if isinstance(payload, dict):
        tampered = json.loads(json.dumps(payload))
        first_key = next(iter(tampered))
        if isinstance(tampered[first_key], (int, float)):
            tampered[first_key] = tampered[first_key] + 1
        elif isinstance(tampered[first_key], str):
            tampered[first_key] = tampered[first_key] + "_tampered"
        else:
            tampered[first_key] = "TAMPERED"
    else:
        tampered = payload

    outcome = run_verification(tampered, timestamp, nonce, tag)
    return jsonify({
        "original_payload": payload,
        "tampered_payload": tampered,
        "timestamp": timestamp,
        "nonce": nonce,
        "tag": tag,
        "result": outcome["result"],
        "reason": outcome["reason"],
        "checks": outcome["checks"],
    })


@app.post("/api/simulate/replay")
def api_sim_replay():
    """Sign a payload, verify once (accepted), then re-verify with same nonce."""
    data = request.get_json(force=True, silent=True) or {}
    payload = data.get("payload", {"action": "transfer", "amount": 500})
    timestamp = time.time()
    nonce = _secrets.token_hex(16)
    tag = compute_hmac(timestamp, nonce, payload)

    first = run_verification(payload, timestamp, nonce, tag)
    second = run_verification(payload, timestamp, nonce, tag)

    return jsonify({
        "payload": payload,
        "timestamp": timestamp,
        "nonce": nonce,
        "tag": tag,
        "first_attempt": {
            "result": first["result"],
            "reason": first["reason"],
            "checks": first["checks"],
        },
        "second_attempt": {
            "result": second["result"],
            "reason": second["reason"],
            "checks": second["checks"],
        },
    })


@app.post("/api/simulate/expired")
def api_sim_expired():
    """Sign with an old timestamp, then verify."""
    data = request.get_json(force=True, silent=True) or {}
    payload = data.get("payload", {"action": "ping"})
    timestamp = time.time() - 120   # 120s ago – outside the 60s window
    nonce = _secrets.token_hex(16)
    tag = compute_hmac(timestamp, nonce, payload)

    outcome = run_verification(payload, timestamp, nonce, tag)
    return jsonify({
        "payload": payload,
        "timestamp": timestamp,
        "nonce": nonce,
        "tag": tag,
        "result": outcome["result"],
        "reason": outcome["reason"],
        "checks": outcome["checks"],
    })


@app.get("/api/events")
def api_events():
    """
    List events with search, filters, sorting and pagination.

    Query params:
      q           free-text search (matches request_id / payload / nonce)
      result      accepted | rejected | all (default all)
      reason      tamper | expired | replay | ok | all
      sort        created_at | timestamp (default created_at)
      order       asc | desc (default desc)
      page        1-based page number (default 1)
      page_size   items per page (default 20, max 100)
    """
    q = request.args.get("q", "").strip()
    result_filter = request.args.get("result", "all")
    reason_filter = request.args.get("reason", "all")
    sort = request.args.get("sort", "created_at")
    order = request.args.get("order", "desc")
    page = max(int(request.args.get("page", 1)), 1)
    page_size = min(max(int(request.args.get("page_size", 20)), 1), 100)

    # whitelist sort columns
    sort_col = "created_at" if sort not in ("created_at", "timestamp") else sort
    order_dir = "DESC" if order.upper() != "ASC" else "ASC"

    clauses = []
    params = []

    if q:
        clauses.append("(request_id LIKE ? OR payload LIKE ? OR nonce LIKE ?)")
        params.extend([f"%{q}%"] * 3)
    if result_filter in ("accepted", "rejected"):
        clauses.append("result = ?")
        params.append(result_filter)
    if reason_filter in ("tamper", "expired", "replay", "ok"):
        clauses.append("reason = ?")
        params.append(reason_filter)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    conn = get_db()

    # total count
    total = conn.execute(f"SELECT COUNT(*) FROM events{where}", params).fetchone()[0]

    rows = conn.execute(
        f"""SELECT id, request_id, payload, timestamp, nonce, tag,
                  result, reason, checks_json, created_at
            FROM events{where}
            ORDER BY {sort_col} {order_dir}
            LIMIT ? OFFSET ?""",
        params + [page_size, (page - 1) * page_size],
    ).fetchall()
    conn.close()

    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "request_id": r["request_id"],
            "payload": r["payload"],
            "timestamp": r["timestamp"],
            "nonce": r["nonce"],
            "tag": r["tag"],
            "result": r["result"],
            "reason": r["reason"],
            "checks": json.loads(r["checks_json"]),
            "created_at": r["created_at"],
        })

    return jsonify({
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total else 0,
    })


@app.get("/api/stats")
def api_stats():
    """Aggregate stats for dashboard cards."""
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    accepted = conn.execute("SELECT COUNT(*) FROM events WHERE result='accepted'").fetchone()[0]
    rejected = conn.execute("SELECT COUNT(*) FROM events WHERE result='rejected'").fetchone()[0]

    reason_counts = {"tamper": 0, "expired": 0, "replay": 0, "ok": 0}
    for row in conn.execute("SELECT reason, COUNT(*) AS c FROM events GROUP BY reason"):
        reason_counts[row["reason"]] = row["c"]

    conn.close()

    return jsonify({
        "total": total,
        "accepted": accepted,
        "rejected": rejected,
        "tamper": reason_counts["tamper"],
        "expired": reason_counts["expired"],
        "replay": reason_counts["replay"],
        "accept_rate": round(accepted / total * 100, 1) if total else 0,
    })


@app.get("/api/health")
def api_health():
    return jsonify({"status": "ok", "time": _iso_now()})


# ---------------------------------------------------------------------------
# Error handlers — always return JSON so the frontend doesn't break
# ---------------------------------------------------------------------------

@app.errorhandler(500)
def handle_500(e):
    return jsonify({"error": "Internal server error", "detail": str(e)}), 500


@app.errorhandler(404)
def handle_404(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(Exception)
def handle_unhandled(e):
    """Catch all unhandled exceptions and return JSON."""
    from flask import abort
    # Re-raise HTTPExceptions so 404, 400 etc. keep their status codes
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return jsonify({"error": e.description, "code": e.code}), e.code
    return jsonify({"error": "Internal server error", "detail": str(e)}), 500


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return send_from_directory(str(STATIC_DIR), "index.html")


@app.get("/<path:path>")
def static_files(path):
    full = STATIC_DIR / path
    if full.is_file():
        return send_from_directory(str(STATIC_DIR), path)
    return send_from_directory(str(STATIC_DIR), "index.html")


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()  # safety net; also called at import time
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)
