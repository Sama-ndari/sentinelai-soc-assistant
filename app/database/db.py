"""
SQLite database connection and initialization.
"""

import aiosqlite
import os
from pathlib import Path


DATABASE_PATH = Path("data/soc_assistant.db")


async def init_database():
    """Initialize the database with required tables."""
    # Ensure data directory exists
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # Create incidents table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                attack_type TEXT,
                severity TEXT,
                description TEXT,
                mitre_attack TEXT,
                recommendations TEXT,
                evidence_summary TEXT,
                llm_analysis TEXT,
                alerts TEXT,
                log_source TEXT,
                events_analyzed INTEGER DEFAULT 0,
                analysis_duration_ms INTEGER,
                status TEXT DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create analysis logs table for tracking
        await db.execute("""
            CREATE TABLE IF NOT EXISTS analysis_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT,
                log_type TEXT,
                entries_processed INTEGER,
                alerts_generated INTEGER,
                llm_tokens_used INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        """)
        
        await db.commit()


async def get_db():
    """Get database connection as async context manager."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    return aiosqlite.connect(DATABASE_PATH)
