import logging
import traceback
from datetime import datetime
from typing import List, Optional

import httpx
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import logging_filters
import models
import sharing
from auth import create_access_token, get_current_user, get_password_hash, verify_password
from config import NOTIFY_SERVICE_URL, PUBLIC_BASE_URL
from database import engine, get_db, search_scans_by_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FIX 4: scrub credentials out of logs before anything is emitted.
logging_filters.install()

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.0.0",
)


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s: %s", request.url, exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc(),
            "path": str(request.url),
        },
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cve_id: Optional[str] = None
    affected_component: str
    remediation_notes: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = None


class ScanOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class ShareCreate(BaseModel):
    password: Optional[str] = Field(default=None, max_length=256)


class ShareOut(BaseModel):
    share_url: str
    expires_at: datetime
    password_protected: bool


class SharedScanOut(BaseModel):
    """Deliberately narrower than ScanOut.

    The only object an unauthenticated third party ever sees, so it is defined
    field-by-field rather than reusing ScanOut. Reusing ScanOut would leak
    owner_id and remediation_notes — internal commentary about how a
    vulnerability will be fixed. Any field added to ScanOut later stays private
    by default.
    """

    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fire_notify(event: str, payload: dict) -> None:
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("Notification service unreachable: %s", exc)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    # FIX 4 (H3, High): the password was previously logged in cleartext on both
    # the attempt and the failure path, copying user credentials into log
    # aggregation and backups where they far outlive the password itself. The
    # failure path was the worse of the two: failed logins routinely contain
    # passwords for *other* systems, typed by mistake. Username only now — it is
    # still needed for audit and brute-force alerting.
    logger.info("Login attempt — username: %s", payload.username)
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning("Failed login — username: %s", payload.username)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if payload.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical | high | medium | low")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.get("/scans/search")
def search_scans(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters")
    # FIX 3b (H2, High): search had no owner filter at all, so it returned
    # every tenant's scans regardless of who asked. Found while fixing C2 —
    # no scanner reported it.
    results = search_scans_by_query(db, q, current_user.id)
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # FIX 3a (H2, High): this filtered on id only, so any authenticated user
    # could read any other tenant's scan by incrementing the id. The owner_id
    # filter matches what update_scan and delete_scan already did. 404 rather
    # than 403 so the endpoint cannot be used to enumerate which ids exist.
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"):
            raise HTTPException(status_code=400, detail="status must be open | in_progress | resolved")
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()



# ---------------------------------------------------------------------------
# Shared report links
# ---------------------------------------------------------------------------

@app.post("/scans/{scan_id}/share", response_model=ShareOut, status_code=201)
def create_share_link(
    scan_id: int,
    payload: ShareCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Mint a 24-hour share link for a scan the caller owns."""
    # Ownership enforced in the query itself. A miss returns 404 rather than
    # 403 so this cannot be used to enumerate which scan IDs exist.
    scan = (
        db.query(models.ScanResult)
        .filter(
            models.ScanResult.id == scan_id,
            models.ScanResult.owner_id == current_user.id,
        )
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    password_hash = None
    if payload.password is not None:
        error = sharing.validate_password_strength(payload.password)
        if error:
            raise HTTPException(status_code=400, detail=error)
        password_hash = sharing.hash_share_password(payload.password)

    token = sharing.generate_share_token()
    expires_at = sharing.utcnow() + sharing.SHARE_TTL

    link = models.ShareLink(
        token_hash=sharing.hash_share_token(token),
        scan_id=scan.id,
        created_by=current_user.id,
        password_hash=password_hash,
        expires_at=expires_at,
    )
    db.add(link)
    db.commit()
    db.refresh(link)

    # Log the event without the token — logging it would put a live credential
    # into log aggregation, where it outlives the 24-hour window.
    logger.info(
        "Share link %s created for scan %s by user %s (protected=%s)",
        link.id, scan.id, current_user.id, password_hash is not None,
    )

    return ShareOut(
        share_url=f"{PUBLIC_BASE_URL}/share/{token}",
        expires_at=expires_at,
        password_protected=password_hash is not None,
    )


@app.get("/share/{token}", response_model=SharedScanOut)
def read_shared_scan(
    response: Response,
    token: str = Path(..., max_length=sharing.MAX_TOKEN_LENGTH),
    password: Optional[str] = Query(default=None, max_length=256),
    x_share_password: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """Public endpoint. No authentication — the token *is* the credential."""
    # Stop the token leaking onward: no-store keeps it out of shared caches,
    # no-referrer stops the browser putting the full URL (token included) into
    # the Referer header of any outbound link on the rendered page.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"

    link = (
        db.query(models.ShareLink)
        .filter(models.ShareLink.token_hash == sharing.hash_share_token(token))
        .first()
    )

    if not link or link.revoked_at is not None:
        raise HTTPException(status_code=404, detail="Share link not found")

    if link.expires_at <= sharing.utcnow():
        # 410 Gone is honest and useful: the token is unguessable, so admitting
        # it expired gives an attacker nothing, and it tells a legitimate
        # auditor to request a fresh link.
        raise HTTPException(status_code=410, detail="Share link has expired")

    if link.password_hash is not None:
        if link.failed_attempts >= sharing.MAX_FAILED_ATTEMPTS:
            raise HTTPException(
                status_code=429, detail="Too many failed attempts; request a new link"
            )

        supplied = x_share_password if x_share_password is not None else password
        if supplied is None:
            raise HTTPException(status_code=401, detail="This link requires a password")

        # FIX 4: the query parameter is kept because the brief specifies it, but
        # it puts a credential in the URL. The header is preferred, access logs
        # are scrubbed, and query-string callers are told to migrate.
        if x_share_password is None:
            response.headers["Deprecation"] = "true"
            response.headers["Warning"] = (
                '299 - "password query parameter is deprecated; '
                'use the X-Share-Password header"'
            )

        if not sharing.verify_share_password(supplied, link.password_hash):
            # Persisted so the limit survives restarts and applies across workers.
            link.failed_attempts += 1
            db.commit()
            logger.warning(
                "Failed attempt %s/%s on share link %s",
                link.failed_attempts, sharing.MAX_FAILED_ATTEMPTS, link.id,
            )
            raise HTTPException(status_code=401, detail="Invalid password")

        if link.failed_attempts:
            link.failed_attempts = 0
            db.commit()

    scan = db.query(models.ScanResult).filter(models.ScanResult.id == link.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Share link not found")

    return scan


@app.delete("/share/{token}", status_code=204)
def revoke_share_link(
    token: str = Path(..., max_length=sharing.MAX_TOKEN_LENGTH),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Kill a link before its 24 hours are up. Only the issuer may revoke."""
    link = (
        db.query(models.ShareLink)
        .filter(
            models.ShareLink.token_hash == sharing.hash_share_token(token),
            models.ShareLink.created_by == current_user.id,
        )
        .first()
    )
    if not link:
        raise HTTPException(status_code=404, detail="Share link not found")
    link.revoked_at = sharing.utcnow()
    db.commit()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}