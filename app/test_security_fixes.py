"""Regression tests for the four Task 3 remediations.

Each test fails against the pre-fix code and passes after, so a future refactor
cannot silently reintroduce the vulnerability.
"""

import base64
import json
import logging
import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import logging_filters  # noqa: E402
from config import ALGORITHM  # noqa: E402
from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

engine = create_engine("sqlite:///./test_security.db", connect_args={"check_same_thread": False})
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
    # Scoped to this module: test_api.py installs its own override at import
    # time, and pytest imports every module before running any test.
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
    return client.post(
        "/auth/login", json={"username": username, "password": password}
    ).json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def make_scan(token, title="Internal finding"):
    return client.post(
        "/scans",
        json={"title": title, "severity": "high", "affected_component": "api"},
        headers=auth_headers(token),
    ).json()["id"]


# --- FIX 1 (C1): JWT none algorithm -----------------------------------------

def _forge_none_token(username="alice"):
    """Hand-build an alg=none JWT.

    python-jose refuses to *create* one, so the attack is assembled manually —
    exactly what an attacker would do with a text editor.
    """
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f'{b64({"alg": "none", "typ": "JWT"})}.{b64({"sub": username})}.'


def test_unsigned_jwt_is_rejected():
    register_and_login()
    assert client.get("/scans", headers=auth_headers(_forge_none_token())).status_code == 401


def test_token_signed_with_wrong_key_is_rejected():
    from jose import jwt
    register_and_login()
    forged = jwt.encode({"sub": "alice"}, "not-the-real-key", algorithm=ALGORITHM)
    assert client.get("/scans", headers=auth_headers(forged)).status_code == 401


def test_valid_token_still_works():
    token = register_and_login()
    assert client.get("/scans", headers=auth_headers(token)).status_code == 200


# --- FIX 2 (C2): SQL injection ----------------------------------------------

def test_tautology_injection_returns_nothing():
    token = register_and_login()
    make_scan(token, "Genuine finding")
    # Pre-fix this returned every row; post-fix it is a literal string search.
    resp = client.get("/scans/search?q=' OR '1'='1", headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_injection_cannot_drop_table():
    token = register_and_login()
    make_scan(token, "Still here")
    client.get("/scans/search?q=x'; DROP TABLE scan_results;--", headers=auth_headers(token))
    # Had the injection executed, this would 500.
    assert client.get("/scans", headers=auth_headers(token)).status_code == 200


def test_search_still_finds_real_matches():
    token = register_and_login()
    make_scan(token, "Reflected XSS in search")
    assert client.get("/scans/search?q=XSS", headers=auth_headers(token)).json()["count"] == 1


def test_like_wildcard_is_escaped():
    token = register_and_login()
    make_scan(token, "No percent sign here")
    # "%%" — pre-fix this became LIKE '%%%%' and matched every row.
    assert client.get("/scans/search?q=%25%25", headers=auth_headers(token)).json()["count"] == 0


# --- FIX 3 (H2): broken access control --------------------------------------

def test_cannot_read_another_users_scan():
    alice = register_and_login()
    scan_id = make_scan(alice, "Alice private finding")
    bob = register_and_login("bob", "bob@example.com", "password456")
    assert client.get(f"/scans/{scan_id}", headers=auth_headers(bob)).status_code == 404


def test_search_does_not_leak_other_users_scans():
    alice = register_and_login()
    make_scan(alice, "Alice secret finding")
    bob = register_and_login("bob", "bob@example.com", "password456")
    assert client.get("/scans/search?q=secret", headers=auth_headers(bob)).json()["count"] == 0


def test_owner_can_still_read_own_scan():
    token = register_and_login()
    scan_id = make_scan(token)
    assert client.get(f"/scans/{scan_id}", headers=auth_headers(token)).status_code == 200


# --- FIX 4 (H3 + H4): credentials in logs -----------------------------------

def test_login_password_not_written_to_logs(caplog):
    client.post(
        "/auth/register",
        json={"username": "carol", "email": "c@example.com", "password": "password123"},
    )
    with caplog.at_level(logging.INFO):
        client.post("/auth/login", json={"username": "carol", "password": "hunter2-wrong"})

    assert "hunter2-wrong" not in caplog.text
    assert "carol" in caplog.text  # username still logged for audit


def test_access_log_redacts_share_password_and_token():
    line = '127.0.0.1 - "GET /share/FwNl7zg_Py_hTZK7m1RyZQ?password=auditor-pass-2026 HTTP/1.1" 200'
    scrubbed = logging_filters.scrub(line)

    assert "auditor-pass-2026" not in scrubbed
    assert "[REDACTED]" in scrubbed
    assert "FwNl7zg_Py_hTZK7m1RyZQ" not in scrubbed  # full token gone
    assert "FwNl7zg_" in scrubbed                    # prefix kept for correlation


def test_filter_mutates_a_real_log_record():
    record = logging.LogRecord(
        name="uvicorn.access", level=logging.INFO, pathname="", lineno=0,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("127.0.0.1", "GET", "/share/abcdefghijklmno?password=s3cr3t", "1.1", 200),
        exc_info=None,
    )
    logging_filters.RedactSecretsFilter().filter(record)
    assert "s3cr3t" not in record.getMessage()


def test_query_password_still_works_but_is_deprecated():
    token = register_and_login()
    scan_id = make_scan(token)
    url = client.post(
        f"/scans/{scan_id}/share", json={"password": "auditor-pass"}, headers=auth_headers(token)
    ).json()["share_url"]
    share_token = url.rsplit("/", 1)[-1]

    via_query = client.get(f"/share/{share_token}?password=auditor-pass")
    assert via_query.status_code == 200
    assert via_query.headers.get("Deprecation") == "true"

    via_header = client.get(f"/share/{share_token}", headers={"X-Share-Password": "auditor-pass"})
    assert via_header.status_code == 200
    assert "Deprecation" not in via_header.headers