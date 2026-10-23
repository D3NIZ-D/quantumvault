import re

import pytest

from quantumvault.server import create_app

FAST_KDF = {"time_cost": 1, "memory_cost": 8_192, "parallelism": 1}
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
MASTER = "correct horse battery staple"


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "vault.json", port=PORT, kdf_params=FAST_KDF)
    c = app.test_client()
    html = c.get("/", base_url=BASE).get_data(as_text=True)
    c.csrf = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
    return c


def call(client, method, path, json=None, csrf=True, base=BASE, **kw):
    headers = {"X-CSRF-Token": client.csrf} if csrf else {}
    return client.open(path, method=method, json=json, headers=headers, base_url=base, **kw)


def setup(client):
    r = call(client, "POST", "/api/setup", {"master_password": MASTER, "confirm_password": MASTER})
    assert r.status_code == 200


def test_full_flow(client):
    assert call(client, "GET", "/api/status").json["initialized"] is False
    setup(client)

    r = call(client, "POST", "/api/entries", {"title": "GitHub", "options": {"length": 48}})
    assert r.status_code == 201
    entry_id = r.json["entry"]["id"]
    password = r.json["password"]
    assert "password" not in r.json["entry"]

    listing = call(client, "GET", "/api/entries").json["entries"]
    assert [e["title"] for e in listing] == ["GitHub"]
    assert "password" not in listing[0]

    assert call(client, "GET", f"/api/entries/{entry_id}/password").json["password"] == password

    r = call(client, "PATCH", f"/api/entries/{entry_id}", {"title": "GitHub (work)"})
    assert r.json["entry"]["title"] == "GitHub (work)"

    r = call(client, "POST", f"/api/entries/{entry_id}/regenerate", {"options": {"length": 64}})
    assert len(r.json["password"]) == 64

    assert call(client, "DELETE", f"/api/entries/{entry_id}").status_code == 200
    assert call(client, "GET", "/api/entries").json["entries"] == []


def test_weak_options_rejected(client):
    setup(client)
    r = call(client, "POST", "/api/entries", {"title": "x", "options": {"length": 20}})
    assert r.status_code == 400
    assert "256" in r.json["error"]


def test_csrf_required(client):
    r = call(client, "POST", "/api/setup", {"master_password": MASTER, "confirm_password": MASTER}, csrf=False)
    assert r.status_code == 403


def test_foreign_origin_rejected(client):
    r = client.post(
        "/api/setup",
        json={"master_password": MASTER, "confirm_password": MASTER},
        headers={"X-CSRF-Token": client.csrf, "Origin": "http://evil.example"},
        base_url=BASE,
    )
    assert r.status_code == 403


def test_dns_rebinding_host_rejected(client):
    assert call(client, "GET", "/api/status", base=f"http://evil.example:{PORT}").status_code == 403


def test_requires_unlock(client):
    setup(client)
    call(client, "POST", "/api/lock")
    assert call(client, "GET", "/api/entries").status_code == 401


def test_unlock_wrong_password(client):
    setup(client)
    call(client, "POST", "/api/lock")
    r = call(client, "POST", "/api/unlock", {"master_password": "nope nope nope"})
    assert r.status_code == 401
    r = call(client, "POST", "/api/unlock", {"master_password": MASTER})
    assert r.status_code == 200
    assert call(client, "GET", "/api/entries").status_code == 200


def test_security_headers(client):
    r = call(client, "GET", "/")
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"
