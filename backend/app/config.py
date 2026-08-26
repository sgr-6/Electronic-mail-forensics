"""
Application configuration using Pydantic Settings.

Loads from .env file or environment variables. All external services
have sensible defaults enabling zero-config local development.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for the Email Forensics Platform."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Core Settings ---
    # database_url: str = "sqlite+aiosqlite:///data.db"
    database_url: str = "postgresql+asyncpg://postgres:AppiSagar%40789@db.jbwksprxtnpbqiuilsml.supabase.co:5432/postgres"

    # --- Neo4j (Optional) ---
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "changeme"
    neo4j_enabled: bool = False

    # --- MaxMind GeoIP ---
    geoip_db_path: str = "./data/GeoLite2.mmdb"

    # --- AbuseIPDB ---
    abuseipdb_api_key: str = ""

    # --- Application ---
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    app_debug: bool = True
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # --- Security ---
    secret_key: str = "dev-secret-key-change-in-production"

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse comma-separated CORS origins into a list."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_sqlite(self) -> bool:
        """Check if using SQLite backend."""
        return "sqlite" in self.database_url.lower()


# Singleton instance
settings = Settings()
