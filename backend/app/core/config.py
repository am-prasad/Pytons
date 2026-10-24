"""
AgentShield Backend — Centralized Configuration
All settings loaded from environment variables with documented defaults.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import List

try:
    from pydantic_settings import BaseSettings
except ImportError:
    try:
        from pydantic import BaseSettings  # type: ignore
    except ImportError:
        from pydantic import BaseModel

        class BaseSettings(BaseModel):  # type: ignore
            def __init__(self, **kwargs):
                # Load .env if present
                if os.path.exists(".env"):
                    try:
                        with open(".env", "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith("#") and "=" in line:
                                    k, v = line.split("=", 1)
                                    k, v = k.strip(), v.strip()
                                    if k not in os.environ:
                                        os.environ[k] = v
                    except Exception:
                        pass

                env_vals = {}
                fields = getattr(self, "model_fields", None) or getattr(self, "__fields__", {})
                for field_name, field_info in fields.items():
                    alias = getattr(field_info, "alias", None) or field_name.upper()
                    if alias in os.environ:
                        raw = os.environ[alias]
                        ann = getattr(field_info, "annotation", None)
                        if ann is int:
                            raw = int(raw)
                        elif ann is float:
                            raw = float(raw)
                        elif ann is bool:
                            raw = str(raw).lower() in ("true", "1", "yes", "t")
                        env_vals[field_name] = raw
                env_vals.update(kwargs)
                super().__init__(**env_vals)

from pydantic import Field


class Settings(BaseSettings):
    # ── Server ───────────────────────────────────────────────────────────────
    backend_host: str = Field(default="0.0.0.0", alias="BACKEND_HOST")
    backend_port: int = Field(default=8000, alias="BACKEND_PORT")
    allowed_origins: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173",
        alias="ALLOWED_ORIGINS",
    )

    # ── Groq LLM (Judge & Agent) ─────────────────────────────────────────────
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    groq_model: str = Field(default="llama-3.1-8b-instant", alias="GROQ_MODEL")
    agent_model: str = Field(default="llama-3.3-70b-versatile", alias="AGENT_MODEL")

    # ── LangSmith ────────────────────────────────────────────────────────────
    langsmith_tracing: bool = Field(default=False, alias="LANGSMITH_TRACING")
    langsmith_api_key: str = Field(default="", alias="LANGSMITH_API_KEY")
    langsmith_project: str = Field(default="agentshield", alias="LANGSMITH_PROJECT")
    langsmith_endpoint: str = Field(
        default="https://api.smith.langchain.com", alias="LANGSMITH_ENDPOINT"
    )

    # ── Storage & Paths ──────────────────────────────────────────────────────
    chroma_persist_directory: str = Field(
        default="./data/chroma", alias="CHROMA_PERSIST_DIRECTORY"
    )
    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/agentshield.db", alias="DATABASE_URL"
    )
    persist_document_text: bool = Field(default=False, alias="PERSIST_DOCUMENT_TEXT")

    # ── Document Upload & Extraction Limits ──────────────────────────────────
    max_upload_bytes: int = Field(default=5242880, alias="MAX_UPLOAD_BYTES")  # 5 MB
    max_pdf_pages: int = Field(default=20, alias="MAX_PDF_PAGES")
    max_llm_calls_per_doc: int = Field(default=6, alias="MAX_LLM_CALLS_PER_DOC")
    max_llm_input_chars: int = Field(default=4000, alias="MAX_LLM_INPUT_CHARS")

    # ── Security & Policy Gate ───────────────────────────────────────────────
    max_input_length: int = Field(default=8000, alias="MAX_INPUT_LENGTH")
    request_timeout_seconds: int = Field(default=30, alias="REQUEST_TIMEOUT_SECONDS")
    outbound_allowed_domains: str = Field(
        default="internal.corp,company.com,partner.org,acme.com",
        alias="OUTBOUND_ALLOWED_DOMAINS",
    )

    # ── Risk Thresholds ──────────────────────────────────────────────────────
    risk_threshold_block: float = Field(default=70.0, alias="RISK_THRESHOLD_BLOCK")
    risk_threshold_quarantine: float = Field(default=35.0, alias="RISK_THRESHOLD_QUARANTINE")
    scanner_suspicious_threshold: float = Field(default=20.0, alias="SCANNER_SUSPICIOUS_THRESHOLD")

    # ── Alerting & Webhooks ──────────────────────────────────────────────────
    slack_webhook_url: str = Field(default="", alias="SLACK_WEBHOOK_URL")
    alert_webhook_url: str = Field(default="", alias="ALERT_WEBHOOK_URL")
    alert_webhook_secret: str = Field(default="", alias="ALERT_WEBHOOK_SECRET")

    # ── Derived helpers ───────────────────────────────────────────────────────
    @property
    def allowed_origins_list(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def outbound_allowed_domains_list(self) -> List[str]:
        return [d.strip().lower() for d in self.outbound_allowed_domains.split(",") if d.strip()]

    @property
    def groq_configured(self) -> bool:
        return bool(self.groq_api_key.strip())

    @property
    def clean_langsmith_project(self) -> str:
        return self.langsmith_project.strip(' "\'') or "pythons"

    @property
    def langsmith_configured(self) -> bool:
        return bool(self.langsmith_api_key.strip()) and self.langsmith_tracing

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        populate_by_name = True
        extra = "ignore"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    s = Settings()
    if s.langsmith_configured:
        os.environ["LANGCHAIN_TRACING_V2"] = "true"
        os.environ["LANGCHAIN_API_KEY"] = s.langsmith_api_key.strip()
        os.environ["LANGCHAIN_PROJECT"] = s.clean_langsmith_project
        os.environ["LANGCHAIN_ENDPOINT"] = s.langsmith_endpoint
        os.environ["LANGSMITH_TRACING"] = "true"
        os.environ["LANGSMITH_API_KEY"] = s.langsmith_api_key.strip()
        os.environ["LANGSMITH_PROJECT"] = s.clean_langsmith_project
        os.environ["LANGSMITH_ENDPOINT"] = s.langsmith_endpoint
    return s
