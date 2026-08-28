from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("ScanResult", back_populates="owner")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    severity = Column(String(20), default="medium")   # critical | high | medium | low
    status = Column(String(20), default="open")        # open | in_progress | resolved
    cve_id = Column(String(30), nullable=True)
    affected_component = Column(String(200), nullable=False)
    remediation_notes = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="scans")

    share_links = relationship(
        "ShareLink", back_populates="scan", cascade="all, delete-orphan"
    )


class ShareLink(Base):
    """A time-limited, optionally password-protected pointer to one scan."""

    __tablename__ = "share_links"

    id = Column(Integer, primary_key=True, index=True)

    # SHA-256 hex digest of the token. The raw token is returned to the caller
    # exactly once and is never persisted.
    token_hash = Column(String(64), unique=True, index=True, nullable=False)

    scan_id = Column(
        Integer, ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)

    # NULL means the link is not password protected.
    password_hash = Column(String(200), nullable=True)

    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)

    failed_attempts = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("ScanResult", back_populates="share_links")