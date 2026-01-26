"""
Data access layer for incidents and analysis logs.
"""

import json
from typing import List, Optional
from datetime import datetime

from app.database.db import get_db
from app.models.incident import IncidentReport, LLMAnalysis


class IncidentRepository:
    """Repository for incident CRUD operations."""
    
    @staticmethod
    async def save(incident: IncidentReport) -> str:
        """Save an incident report to the database."""
        async with await get_db() as db:
            await db.execute(
                """
                INSERT INTO incidents (
                    id, title, attack_type, severity, description,
                    mitre_attack, recommendations, evidence_summary,
                    llm_analysis, alerts, log_source, events_analyzed,
                    analysis_duration_ms, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.id,
                    incident.title,
                    incident.attack_type,
                    incident.severity,
                    incident.description,
                    json.dumps(incident.mitre_attack),
                    json.dumps(incident.recommendations),
                    json.dumps(incident.evidence_summary),
                    json.dumps(incident.llm_analysis.model_dump()) if incident.llm_analysis else None,
                    json.dumps([a for a in incident.alerts]),
                    incident.log_source,
                    incident.events_analyzed,
                    incident.analysis_duration_ms,
                    incident.status,
                    incident.created_at.isoformat(),
                )
            )
            await db.commit()
        return incident.id
    
    @staticmethod
    async def get_by_id(incident_id: str) -> Optional[IncidentReport]:
        """Retrieve an incident by ID."""
        async with await get_db() as db:
            db.row_factory = _dict_factory
            cursor = await db.execute(
                "SELECT * FROM incidents WHERE id = ?",
                (incident_id,)
            )
            row = await cursor.fetchone()
            
            if not row:
                return None
            
            return _row_to_incident(row)
    
    @staticmethod
    async def get_all(limit: int = 50, offset: int = 0) -> List[IncidentReport]:
        """Retrieve all incidents with pagination."""
        async with await get_db() as db:
            db.row_factory = _dict_factory
            cursor = await db.execute(
                """
                SELECT * FROM incidents 
                ORDER BY created_at DESC 
                LIMIT ? OFFSET ?
                """,
                (limit, offset)
            )
            rows = await cursor.fetchall()
            
            return [_row_to_incident(row) for row in rows]
    
    @staticmethod
    async def get_by_severity(severity: str) -> List[IncidentReport]:
        """Retrieve incidents by severity level."""
        async with await get_db() as db:
            db.row_factory = _dict_factory
            cursor = await db.execute(
                """
                SELECT * FROM incidents 
                WHERE severity = ?
                ORDER BY created_at DESC
                """,
                (severity,)
            )
            rows = await cursor.fetchall()
            
            return [_row_to_incident(row) for row in rows]
    
    @staticmethod
    async def update_status(incident_id: str, status: str) -> bool:
        """Update incident status."""
        async with await get_db() as db:
            cursor = await db.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                (status, incident_id)
            )
            await db.commit()
            return cursor.rowcount > 0


def _dict_factory(cursor, row):
    """Convert SQLite row to dictionary."""
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


def _row_to_incident(row: dict) -> IncidentReport:
    """Convert database row to IncidentReport model."""
    llm_analysis = None
    if row.get("llm_analysis"):
        llm_data = json.loads(row["llm_analysis"])
        llm_analysis = LLMAnalysis(**llm_data)
    
    return IncidentReport(
        id=row["id"],
        title=row["title"],
        attack_type=row.get("attack_type", ""),
        severity=row.get("severity", "medium"),
        description=row.get("description", ""),
        mitre_attack=json.loads(row.get("mitre_attack", "[]")),
        recommendations=json.loads(row.get("recommendations", "[]")),
        evidence_summary=json.loads(row.get("evidence_summary", "{}")),
        llm_analysis=llm_analysis,
        alerts=json.loads(row.get("alerts", "[]")),
        log_source=row.get("log_source"),
        events_analyzed=row.get("events_analyzed", 0),
        analysis_duration_ms=row.get("analysis_duration_ms"),
        status=row.get("status", "open"),
        created_at=datetime.fromisoformat(row["created_at"]) if row.get("created_at") else datetime.utcnow(),
    )
