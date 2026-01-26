"""
Incident report model - final output combining detection + LLM analysis.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict
import uuid


class LLMAnalysis(BaseModel):
    """
    Analysis output from the LLM.
    Structured to ensure consistent, parseable responses.
    """
    
    attack_type: str = Field(
        description="Classification of the attack type"
    )
    severity: str = Field(
        description="Assessed severity (low/medium/high/critical)"
    )
    confidence: str = Field(
        description="Confidence in the analysis (low/medium/high)"
    )
    description: str = Field(
        description="2-3 sentence summary of the incident"
    )
    mitre_attack: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs"
    )
    impact_assessment: str = Field(
        description="Assessment of potential impact"
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Recommended response actions"
    )
    false_positive_likelihood: str = Field(
        default="medium",
        description="Likelihood this is a false positive"
    )


class IncidentReport(BaseModel):
    """
    Complete incident report combining rule-based detection
    with LLM-powered analysis.
    
    This is the final output shown to SOC analysts.
    """
    
    id: str = Field(
        default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}",
        description="Unique incident identifier"
    )
    title: str = Field(
        description="Incident title/summary"
    )
    attack_type: str = Field(
        description="Type of attack detected"
    )
    severity: str = Field(
        description="Overall severity assessment"
    )
    description: str = Field(
        description="Detailed description of the incident"
    )
    mitre_attack: List[str] = Field(
        default_factory=list,
        description="Mapped MITRE ATT&CK techniques"
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Recommended response actions"
    )
    evidence_summary: dict = Field(
        default_factory=dict,
        description="Summary of evidence that triggered the alert"
    )
    llm_analysis: Optional[LLMAnalysis] = Field(
        default=None,
        description="Full LLM analysis if available"
    )
    alerts: List[dict] = Field(
        default_factory=list,
        description="Raw alerts that contributed to this incident"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the incident was created"
    )
    status: str = Field(
        default="open",
        description="Incident status (open/investigating/resolved/closed)"
    )
    
    # Analysis metadata
    log_source: Optional[str] = Field(
        default=None,
        description="Source of the analyzed logs"
    )
    events_analyzed: int = Field(
        default=0,
        description="Total number of log events analyzed"
    )
    analysis_duration_ms: Optional[int] = Field(
        default=None,
        description="Time taken for analysis in milliseconds"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "INC-A1B2C3D4",
                "title": "SSH Brute Force Attack Detected",
                "attack_type": "Credential Brute Force",
                "severity": "high",
                "description": "A sustained brute force attack was detected targeting SSH authentication. "
                              "47 failed login attempts were observed from IP 192.168.1.100 over 5 minutes, "
                              "targeting multiple user accounts including admin, root, and ubuntu.",
                "mitre_attack": ["T1110.001", "T1110.003"],
                "recommendations": [
                    "Block source IP 192.168.1.100 at the firewall",
                    "Enable account lockout policies",
                    "Implement fail2ban or similar rate limiting",
                    "Review targeted accounts for compromise indicators"
                ],
                "evidence_summary": {
                    "source_ip": "192.168.1.100",
                    "failed_attempts": 47,
                    "targeted_accounts": ["admin", "root", "ubuntu"],
                    "time_window": "5 minutes"
                },
                "created_at": "2024-01-15T03:30:00Z",
                "status": "open",
                "events_analyzed": 1247
            }
        }
    )
