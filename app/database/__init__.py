"""
Database module for SOC Assistant.
"""

from app.database.db import init_database, get_db
from app.database.repositories import IncidentRepository

__all__ = ["init_database", "get_db", "IncidentRepository"]
