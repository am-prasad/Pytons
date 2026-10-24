"""
AgentShield Storage Layer
SQLite-based persistence for security events and evaluation results.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.schemas.models import SecurityEvent, EvaluationResult

import logging

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class SecurityEventModel(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, nullable=False)
    request_id = Column(String(64), nullable=False)
    session_id = Column(String(64), nullable=True)
    timestamp = Column(DateTime, nullable=False)
    source_type = Column(String(64), nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_category = Column(String(16), nullable=False)
    policy_decision = Column(String(16), nullable=False)
    attack_types = Column(Text, nullable=False, default="[]")  # JSON
    execution_mode = Column(String(32), nullable=False)
    latency_ms = Column(Float, nullable=False)
    summary = Column(Text, nullable=False, default="")


class EvaluationRunModel(Base):
    __tablename__ = "evaluation_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), unique=True, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    result_json = Column(Text, nullable=False)


# ─── Database setup ───────────────────────────────────────────────────────────

def _create_engine():
    settings = get_settings()
    db_url = settings.database_url
    # For SQLite, use StaticPool for async-compatible single-thread use
    if "sqlite" in db_url:
        # Strip async driver for sync SQLAlchemy ORM
        sync_url = db_url.replace("+aiosqlite", "")
        return create_engine(
            sync_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(db_url)


_engine = None
_SessionLocal = None


def init_db() -> None:
    """Initialize database tables. Safe to call multiple times."""
    global _engine, _SessionLocal
    import os
    settings = get_settings()
    # Ensure data directory exists
    db_path = settings.database_url.replace("sqlite+aiosqlite:///", "").replace("sqlite:///", "")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    _engine = _create_engine()
    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    logger.info("Database initialized")


def get_session() -> Session:
    global _SessionLocal
    if _SessionLocal is None:
        init_db()
    return _SessionLocal()


# ─── Event persistence ────────────────────────────────────────────────────────

def save_security_event(event: SecurityEvent) -> None:
    try:
        with get_session() as db:
            model = SecurityEventModel(
                event_id=event.event_id,
                request_id=event.request_id,
                session_id=event.session_id,
                timestamp=event.timestamp,
                source_type=event.source_type,
                risk_score=event.risk_score,
                risk_category=event.risk_category,
                policy_decision=event.policy_decision,
                attack_types=json.dumps(event.attack_types),
                execution_mode=event.execution_mode,
                latency_ms=event.latency_ms,
                summary=event.summary,
            )
            db.add(model)
            db.commit()
    except Exception as exc:
        logger.warning("Failed to save security event: %s", exc)


def list_security_events(page: int = 1, page_size: int = 50) -> tuple[List[SecurityEvent], int]:
    try:
        with get_session() as db:
            total = db.query(SecurityEventModel).count()
            offset = (page - 1) * page_size
            rows = (
                db.query(SecurityEventModel)
                .order_by(SecurityEventModel.timestamp.desc())
                .offset(offset)
                .limit(page_size)
                .all()
            )
            events = [
                SecurityEvent(
                    event_id=r.event_id,
                    request_id=r.request_id,
                    session_id=r.session_id,
                    timestamp=r.timestamp,
                    source_type=r.source_type,
                    risk_score=r.risk_score,
                    risk_category=r.risk_category,
                    policy_decision=r.policy_decision,
                    attack_types=json.loads(r.attack_types or "[]"),
                    execution_mode=r.execution_mode,
                    latency_ms=r.latency_ms,
                    summary=r.summary,
                )
                for r in rows
            ]
            return events, total
    except Exception as exc:
        logger.warning("Failed to list security events: %s", exc)
        return [], 0


def get_security_event(event_id: str) -> Optional[SecurityEvent]:
    try:
        with get_session() as db:
            row = db.query(SecurityEventModel).filter(SecurityEventModel.event_id == event_id).first()
            if not row:
                return None
            return SecurityEvent(
                event_id=row.event_id,
                request_id=row.request_id,
                session_id=row.session_id,
                timestamp=row.timestamp,
                source_type=row.source_type,
                risk_score=row.risk_score,
                risk_category=row.risk_category,
                policy_decision=row.policy_decision,
                attack_types=json.loads(row.attack_types or "[]"),
                execution_mode=row.execution_mode,
                latency_ms=row.latency_ms,
                summary=row.summary,
            )
    except Exception as exc:
        logger.warning("Failed to get security event: %s", exc)
        return None


# ─── Evaluation run persistence ───────────────────────────────────────────────

def save_evaluation_result(result: EvaluationResult) -> None:
    try:
        with get_session() as db:
            model = EvaluationRunModel(
                run_id=result.run_id,
                timestamp=result.timestamp,
                result_json=result.model_dump_json(),
            )
            db.add(model)
            db.commit()
    except Exception as exc:
        logger.warning("Failed to save evaluation result: %s", exc)


def get_latest_evaluation() -> Optional[EvaluationResult]:
    try:
        with get_session() as db:
            row = (
                db.query(EvaluationRunModel)
                .order_by(EvaluationRunModel.timestamp.desc())
                .first()
            )
            if not row:
                return None
            return EvaluationResult.model_validate_json(row.result_json)
    except Exception as exc:
        logger.warning("Failed to get latest evaluation: %s", exc)
        return None
