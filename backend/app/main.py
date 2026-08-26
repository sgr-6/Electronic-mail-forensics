"""
FastAPI application factory for the Email Forensics Platform.

Configures:
- CORS middleware for frontend communication
- Lifespan events (database initialization on startup)
- API router mounting
- Health check endpoint
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.api.routes import router as api_router

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.app_debug else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize database tables on startup."""
    logger.info("Starting Email Forensics Platform...")
    logger.info("Database: %s", settings.database_url)
    logger.info("Neo4j enabled: %s", settings.neo4j_enabled)

    # Create database tables
    await init_db()
    logger.info("Database tables initialized")

    yield

    logger.info("Shutting down Email Forensics Platform...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AI Email Threat Detection & Forensic Intelligence Platform",
        description=(
            "Production-grade email forensics platform combining deep header analysis, "
            "hop-by-hop geolocation tracing, sender authentication (SPF/DKIM/DMARC), "
            "AI-powered threat classification, and graph-based campaign attribution."
        ),
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # --- CORS Middleware ---
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Mount API routes ---
    app.include_router(api_router)

    # --- Health check ---
    @app.get("/health", tags=["system"])
    async def health_check():
        return {
            "status": "healthy",
            "service": "email-forensics-platform",
            "version": "1.0.0",
        }

    return app


# Application instance for uvicorn
app = create_app()
