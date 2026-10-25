"""Tests for valid, tampered, replayed, expired and concurrent-duplicate requests."""
import hmac
import hashlib
import json
import time

import pytest


def _sign(app, payload):
    """Helper: sign a payload using the app's own function."""
    ts = time.time()
    nonce = "nonce-" + str(hash(ts))[:8]
    tag = app.compute_hmac(ts, nonce, payload)
    return ts, nonce, tag


def test_valid_request_accepted(client, app):
    payload = {"amount": 100, "recipient": "alice"}
    ts, nonce, tag = _sign(app, payload)
    resp = client.post("/api/verify", json={
        "payload": payload, "timestamp": ts, "nonce": nonce, "tag": tag,
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["result"] == "accepted"
    assert data["reason"] == "ok"
    assert len(data["checks"]) == 3
    assert all(c["status"] == "pass" for c in data["checks"])


def test_tampered_payload_rejected(client, app):
    payload = {"amount": 100, "recipient": "alice"}
    ts, nonce, tag = _sign(app, payload)
    # tamper
    tampered = dict(payload)
    tampered["amount"] = 999
    resp = client.post("/api/verify", json={
        "payload": tampered, "timestamp": ts, "nonce": nonce, "tag": tag,
    })
    data = resp.get_json()
    assert data["result"] == "rejected"
    assert data["reason"] == "tamper"
    assert data["checks"][0]["status"] == "fail"


def test_expired_request_rejected(client, app):
    payload = {"action": "ping"}
    ts = time.time() - 120
    nonce = "expired-nonce"
    tag = app.compute_hmac(ts, nonce, payload)
    resp = client.post("/api/verify", json={
        "payload": payload, "timestamp": ts, "nonce": nonce, "tag": tag,
    })
    data = resp.get_json()
    assert data["result"] == "rejected"
    assert data["reason"] == "expired"
    assert data["checks"][0]["status"] == "pass"   # HMAC still valid
    assert data["checks"][1]["status"] == "fail"


def test_replay_rejected(client, app):
    payload = {"action": "transfer", "amount": 500}
    ts, nonce, tag = _sign(app, payload)
    r1 = client.post("/api/verify", json={
        "payload": payload, "timestamp": ts, "nonce": nonce, "tag": tag,
    })
    assert r1.get_json()["result"] == "accepted"
    r2 = client.post("/api/verify", json={
        "payload": payload, "timestamp": ts, "nonce": nonce, "tag": tag,
    })
    data = r2.get_json()
    assert data["result"] == "rejected"
    assert data["reason"] == "replay"
    assert data["checks"][0]["status"] == "pass"
    assert data["checks"][1]["status"] == "pass"
    assert data["checks"][2]["status"] == "fail"


def test_concurrent_duplicate_replay(client, app):
    """Two simultaneous requests with the same nonce must result in exactly one accept."""
    import threading
    payload = {"action": "concurrent", "amount": 1}
    ts, nonce, tag = _sign(app, payload)

    results = []

    def send():
        r = client.post("/api/verify", json={
            "payload": payload, "timestamp": ts, "nonce": nonce, "tag": tag,
        })
        results.append(r.get_json()["result"])

    threads = [threading.Thread(target=send) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    accepted_count = results.count("accepted")
    rejected_count = results.count("rejected")
    assert accepted_count == 1
    assert rejected_count == 1


def test_sign_endpoint(client):
    resp = client.post("/api/sign", json={"payload": {"hello": "world"}})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "tag" in data
    assert "nonce" in data
    assert "timestamp" in data
    assert "payload" in data


def test_simulate_tamper(client):
    resp = client.post("/api/simulate/tamper", json={"payload": {"amount": 100}})
    data = resp.get_json()
    assert data["result"] == "rejected"
    assert data["reason"] == "tamper"


def test_simulate_replay(client):
    resp = client.post("/api/simulate/replay", json={"payload": {"action": "test"}})
    data = resp.get_json()
    assert data["first_attempt"]["result"] == "accepted"
    assert data["second_attempt"]["result"] == "rejected"
    assert data["second_attempt"]["reason"] == "replay"


def test_simulate_expired(client):
    resp = client.post("/api/simulate/expired", json={"payload": {"action": "ping"}})
    data = resp.get_json()
    assert data["result"] == "rejected"
    assert data["reason"] == "expired"


def test_events_pagination(client, app):
    for i in range(25):
        payload = {"index": i}
        ts, nonce, tag = _sign(app, payload)
        client.post("/api/verify", json={
            "payload": payload, "timestamp": ts, "nonce": f"pg-{i}", "tag": tag,
        })
    resp = client.get("/api/events?page=1&page_size=10")
    data = resp.get_json()
    assert data["total"] == 25
    assert len(data["items"]) == 10
    assert data["total_pages"] == 3


def test_stats(client, app):
    # one valid
    ts, nonce, tag = _sign(app, {"x": 1})
    client.post("/api/verify", json={"payload": {"x": 1}, "timestamp": ts, "nonce": nonce, "tag": tag})
    resp = client.get("/api/stats")
    data = resp.get_json()
    assert data["total"] >= 1
    assert data["accepted"] >= 1


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"
