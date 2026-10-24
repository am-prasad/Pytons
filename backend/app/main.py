"""
AgentShield FastAPI Application Entry Point
"""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import router
from app.core.config import get_settings
from app.storage.database import init_db

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="AgentShield API",
        description=(
            "AI Agent Security Pipeline: Prompt Injection Detection & Prevention\n\n"
          
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS — origins configured via environment variable
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    app.include_router(router)

    @app.on_event("startup")
    async def startup() -> None:
        logger.info("AgentShield starting up...")
        # Ensure data directory exists
        os.makedirs("./data", exist_ok=True)
        os.makedirs(settings.chroma_persist_directory, exist_ok=True)
        init_db()

        # Configure LangSmith if available
        if settings.langsmith_configured:
            os.environ["LANGCHAIN_TRACING_V2"] = "true"
            os.environ["LANGCHAIN_API_KEY"] = settings.langsmith_api_key
            os.environ["LANGCHAIN_PROJECT"] = settings.langsmith_project
            os.environ["LANGCHAIN_ENDPOINT"] = settings.langsmith_endpoint
            logger.info("LangSmith tracing enabled")
        else:
            logger.info("LangSmith not configured — local trace only")

        exec_mode = "FULL" if settings.groq_configured else "LOCAL_BASELINE"
        logger.info("Execution mode: %s", exec_mode)
        logger.info("AgentShield ready on %s:%s", settings.backend_host, settings.backend_port)

    @app.on_event("shutdown")
    async def shutdown() -> None:
        logger.info("AgentShield shutting down")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.backend_host,
        port=settings.backend_port,
        reload=True,
    )
