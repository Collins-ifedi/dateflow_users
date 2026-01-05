# dataflow_users/backend/users/database.py

import os
import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError

# Import Base from models so we can access metadata for init_db
# Note: In a strict production setup with Alembic, init_db is rarely used, 
# but we keep it here for your current workflow.
from .models import Base

# ======================================================
# CONFIGURATION
# ======================================================

# Setup Logger
logger = logging.getLogger("uvicorn")

def get_database_url() -> str:
    """
    Retrieves the database URL from environment variables and processes it
    to ensure compatibility with SQLAlchemy AsyncPG.
    """
    db_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./dataflow_users.db")

    # FIX FOR RENDER / HEROKU:
    # They often provide URLs starting with 'postgres://', but SQLAlchemy 
    # async requires 'postgresql+asyncpg://'.
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
    
    return db_url

DATABASE_URL = get_database_url()

# ======================================================
# ASYNC ENGINE & SESSION
# ======================================================

# Production Engine Configuration
engine = create_async_engine(
    DATABASE_URL,
    echo=False,                  # Set to True only for debugging SQL queries
    future=True,
    pool_pre_ping=True,          # Vital for production: checks connection health before use
    pool_size=20,                # Number of permanent connections in the pool
    max_overflow=10              # Max "extra" connections for traffic spikes
)

# Async Session Factory
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

# ======================================================
# DEPENDENCY INJECTION
# ======================================================

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides a database session.
    Ensures the session is closed after the request is finished.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except SQLAlchemyError as e:
            logger.error(f"Database error: {str(e)}")
            await session.rollback()
            raise
        finally:
            await session.close()

# ======================================================
# INITIALIZATION UTILS
# ======================================================

async def init_db():
    """
    Creates database tables.
    NOTE: In production, it is recommended to use Alembic for migrations 
    instead of create_all.
    """
    try:
        async with engine.begin() as conn:
            # Import all models here so they are registered with Base.metadata
            # (This import is inside the function to avoid circular dependency issues at module level)
            from .models import User, Match, Message, Like, Call, Report, Verification
            
            await conn.run_sync(Base.metadata.create_all)
        logger.info("✅ Database tables checked/initialized.")
    except Exception as e:
        logger.error(f"❌ Error initializing database: {e}")

async def close_db_connection():
    """
    Closes the database connection pool. Useful for graceful shutdowns.
    """
    await engine.dispose()
    logger.info("Database connection closed.")