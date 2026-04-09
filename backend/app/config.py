from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql://qps_user:qps_pass123@localhost:5432/qps_db"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"

    # Auth
    SECRET_KEY: str = "quantum-proof-super-secret-key-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    # App
    ENVIRONMENT: str = "development"
    APP_NAME: str = "Quantum-Proof Systems Scanner"
    APP_VERSION: str = "1.0.0"

    # Scanning
    SCAN_RESULTS_DIR: str = "/app/scan_results"
    MAX_CONCURRENT_SCANS: int = 4
    SCAN_RATE_LIMIT_DELAY: float = 0.5  # seconds between probes
    CT_CACHE_TTL_HOURS: int = 24  # TTL for CT log redis cache

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
