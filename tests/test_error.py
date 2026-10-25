"""Test that 400 errors return JSON, not HTML."""
import json


def test_400_returns_json(client):
    resp = client.post('/api/verify', json={})
    assert resp.status_code == 400
    assert resp.content_type == 'application/json'
    data = resp.get_json()
    assert 'error' in data


def test_500_returns_json(client):
    # Force a 500 by breaking the DB path
    import app as app_module
    app_module.DB_PATH = '/nonexistent/path/db.db'
    resp = client.get('/api/stats')
    assert resp.status_code == 500
    assert resp.content_type == 'application/json'
    data = resp.get_json()
    assert 'error' in data
