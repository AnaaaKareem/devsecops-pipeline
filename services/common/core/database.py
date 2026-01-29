"""
Database configuration and session management.

This module handles the database connection using SQLAlchemy, configures SQLite
specific optimizations (WAL mode), and provides a dependency for obtaining DB sessions.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# Import from Vault secrets module (falls back to env vars if Vault unavailable)
from .secrets import get_database_url

# --- DATABASE URL CONFIGURATION ---
# Supports PostgreSQL (production) or SQLite (development/testing)
DATABASE_URL = get_database_url() 

# SQLite requires check_same_thread=False for multi-threaded access
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)

# --- WAL MODE CONFIGURATION (SQLite only) ---
# Write-Ahead Logging allows concurrent reads during writes
# Prevents "database is locked" errors under high load
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if "sqlite" in str(getattr(engine.url, "drivername", "")):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")      # Enable WAL mode
        cursor.execute("PRAGMA synchronous=NORMAL")   # Balance speed/safety
        cursor.close()
    else:
        pass  # Skip PRAGMA for PostgreSQL and other databases

# Session factory - creates new sessions bound to engine
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for SQLAlchemy models
Base = declarative_base()

def get_db():
    """
    Dependency generator for FastAPI endpoints.
    Creates a session, yields it, then closes on completion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()  # Return connection to pool