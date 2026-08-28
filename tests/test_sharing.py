import os
import sys
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import models  # noqa: E402
import sharing  # noqa: E402
from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_share.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    # Scoped to this module on purpose. test_api.py installs its own override at
    # import time; pytest imports every test module before running any test, so
    # a module-level assignment here would silently hijack that suite's database.
    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    if previous is None:
        app.dependency_overrides.pop(get_db, None)
    else:
        app.dependency_overrides[get_db] = previous


def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_scan(token, title="SQLi in login form"):
    resp = client.post(
        "/scans",
        json={
            "title": title,
            "description": "Internal detail",
            "severity": "high",
            "cve_id": "CVE-2024-0001",
            "affected_component": "auth-service",
            "remediation_notes": "Rotate the prod DB credential on Friday",
        },
        headers=auth_headers(token),
    )
    return resp.json()["id"]


def token_from_url(share_url):
    return share_url.rsplit("/", 1)[-1]


# --- happy path -------------------------------------------------------------

def test_share_without_password_returns_scan():
    jwt = register_and_login()
    scan_id = create_scan(jwt)

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(jwt))
    assert resp.status_code == 201
    share_url = resp.json()["share_url"]
    assert share_url.startswith("http://localhost:8000/share/")

    public = client.get(f"/share/{token_from_url(share_url)}")
    assert public.status_code == 200
    assert public.json()["title"] == "SQLi in login form"


def test_public_response_omits_internal_fields():
    jwt = register_and_login()
    scan_id = create_scan(jwt)
    url = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(jwt)).json()["share_url"]

    body = client.get(f"/share/{token_from_url(url)}").json()
    assert "remediation_notes" not in body
    assert "owner_id" not in body


def test_security_headers_present():
    jwt = register_and_login()
    scan_id = create_scan(jwt)
    url = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(jwt)).json()["share_url"]

    resp = client.get(f"/share/{token_from_url(url)}")
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["referrer-policy"] == "no-referrer"


# --- password protection ----------------------------------------------------

def test_password_protected_link_requires_password():
    jwt = register_and_login()
    scan_id = create_scan(jwt)
    url = client.post(
        f"/scans/{scan_id}/share", json={"password": "correct-horse"}, headers=auth_headers(jwt)
    ).json()["share_url"]
    token = token_from_url(url)

    assert client.get(f"/share/{token}").status_code == 401
    assert client.get(f"/share/{token}?password=wrong-one").status_code == 401
    assert client.get(f"/share/{token}?password=correct-horse").status_code == 200


def test_password_accepted_via_header():
    jwt = register_and_login()
    scan_id = create_scan(jwt)
    url = client.post(
        f"/scans/{scan_id}/share", json={"password": "correct-horse"}, headers=auth_headers(jwt)
    ).json()["share_url"]

    resp = client.get(
        f"/share/{token_from_url(url)}", headers={"X-Share-Password": "correct-horse"}
    )
    assert resp.status_code == 200


def test_weak_password_rejected():
    jwt = register_and_login()
    scan_id = create_scan(jwt)
    resp = client.post(f"/scans/{scan_id}/share", json={"password": "short"}, headers=auth_headers(jwt))
    assert resp.status_code == 400


def test_brute_force_lockout():
    jwt = register_and_login()
    scan_id = create_scan(jwt)
    url = client.post(
        f"/scans/{scan_id}/share", json={"password": "correct-horse"}, headers=auth_headers(jwt)
    ).json()["share_url"]
    token = token_from_url(url)

    for _ in range(sharing.MAX_FAILED_ATTEMPTS):
        client.get(f"/share/{token}?password=nope")

    # Even the correct password is refused once the link is locked.
    assert client.get(f"/share/{token}?password=correct-horse").status_code == 429


# --- expiry, revocation, authz ---------------------------------------------

def test_expired_link_returns_410():
    jwt = register_and_login()
    scan_id = create_scan(jwt)
    url = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(jwt)).json()["share_url"]
    token = token_from_url(url)

    db = TestingSessionLocal()
    link = db.query(models.ShareLink).first()
    link.expires_at = sharing.utcnow() - timedelta(minutes=1)
    db.commit()
    db.close()

    assert client.get(f"/share/{token}").status_code == 410


def test_ttl_is_24_hours():
    jwt = register_and_login()
    scan_id = create_scan(jwt)
    client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(jwt))

    db = TestingSessionLocal()
    link = db.query(models.ShareLink).first()
    delta = link.expires_at - link.created_at
    db.close()
    assert timedelta(hours=23, minutes=59) < delta < timedelta(hours=24, minutes=1)


def test_cannot_share_another_users_scan():
    alice = register_and_login()
    scan_id = create_scan(alice)
    bob = register_and_login("bob", "bob@example.com", "password456")

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(bob))
    assert resp.status_code == 404


def test_share_requires_authentication():
    assert client.post("/scans/1/share", json={}).status_code in (401, 403)


def test_revoked_link_is_dead():
    jwt = register_and_login()
    scan_id = create_scan(jwt)
    url = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(jwt)).json()["share_url"]
    token = token_from_url(url)

    assert client.delete(f"/share/{token}", headers=auth_headers(jwt)).status_code == 204
    assert client.get(f"/share/{token}").status_code == 404


def test_unknown_token_returns_404():
    assert client.get("/share/definitely-not-a-real-token").status_code == 404


# --- storage properties -----------------------------------------------------

def test_raw_token_is_not_stored():
    jwt = register_and_login()
    scan_id = create_scan(jwt)
    url = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(jwt)).json()["share_url"]
    token = token_from_url(url)

    db = TestingSessionLocal()
    link = db.query(models.ShareLink).first()
    db.close()
    assert link.token_hash != token
    assert link.token_hash == sharing.hash_share_token(token)


def test_tokens_are_unique_and_high_entropy():
    tokens = {sharing.generate_share_token() for _ in range(500)}
    assert len(tokens) == 500
    assert all(len(t) >= 40 for t in tokens)