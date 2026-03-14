"""
Main FastAPI Application
"""
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import IntegrityError
from app.config import settings
from app.database import engine, SessionLocal, Base
from app.models.models import User, UserRole
from app.auth.auth import get_password_hash
from app.routers import auth_router, scans_router, dashboard_router, assets_router
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and seed data on startup."""
    logger.info("Starting Quantum-Proof Systems Scanner API...")
    Base.metadata.create_all(bind=engine)
    _seed_default_users()
    logger.info("✅ Database ready, default users seeded.")
    yield
    logger.info("Shutting down...")


def _seed_default_users():
    """Create default users for each role."""
    db = SessionLocal()
    default_users = [
        {"username": "admin", "email": "admin@qps.local", "password": "admin123", "role": UserRole.ADMIN},
        {"username": "analyst", "email": "analyst@qps.local", "password": "analyst123", "role": UserRole.SECURITY_ANALYST},
        {"username": "compliance", "email": "compliance@qps.local", "password": "comply123", "role": UserRole.COMPLIANCE_OFFICER},
        {"username": "soc", "email": "soc@qps.local", "password": "soc123", "role": UserRole.SOC_TEAM},
        {"username": "manager", "email": "manager@qps.local", "password": "manager123", "role": UserRole.MANAGEMENT},
    ]
    for u in default_users:
        existing = db.query(User).filter(User.username == u["username"]).first()
        if not existing:
            user = User(
                id=str(uuid.uuid4()),
                username=u["username"],
                email=u["email"],
                hashed_password=get_password_hash(u["password"]),
                role=u["role"],
            )
            db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
    finally:
        db.close()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Quantum-Proof Systems Scanner API - Team Spand, PSB Hackathon 2026",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(dashboard_router)
app.include_router(assets_router)


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }
