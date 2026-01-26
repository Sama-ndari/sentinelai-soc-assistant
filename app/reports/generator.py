"""
Incident report generator.
"""

from datetime import datetime
from typing import List, Dict, Any

from app.models.alert import Alert
from app.models.incident import IncidentReport, LLMAnalysis


class ReportGenerator:
    """
    Generates incident reports from detection results and LLM analysis.
    
    Combines:
    - Rule-based detection alerts
    - LLM reasoning and recommendations
    - Metadata and context
    
    Into a cohesive incident report suitable for SOC workflows.
    """
    
    def generate(
        self,
        alerts: List[Alert],
        llm_analysis: LLMAnalysis,
        evidence: Dict[str, Any],
        log_source: str,
        events_analyzed: int,
        analysis_duration_ms: int = 0,
    ) -> IncidentReport:
        """
        Generate a complete incident report.
        
        Args:
            alerts: Detection alerts
            llm_analysis: LLM analysis results
            evidence: Aggregated evidence
            log_source: Type of logs analyzed
            events_analyzed: Number of log entries processed
            analysis_duration_ms: Time taken for analysis
            
        Returns:
            Complete IncidentReport
        """
        # Generate title
        title = self._generate_title(alerts, llm_analysis)
        
        # Build evidence summary (for human consumption)
        evidence_summary = self._build_evidence_summary(alerts, evidence)
        
        # Serialize alerts for storage
        alert_dicts = [
            {
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "severity": a.severity.value,
                "description": a.description,
                "source_ips": a.source_ips,
                "affected_users": a.affected_users,
                "evidence": a.evidence,
            }
            for a in alerts
        ]
        
        return IncidentReport(
            title=title,
            attack_type=llm_analysis.attack_type,
            severity=llm_analysis.severity,
            description=llm_analysis.description,
            mitre_attack=llm_analysis.mitre_attack,
            recommendations=llm_analysis.recommendations,
            evidence_summary=evidence_summary,
            llm_analysis=llm_analysis,
            alerts=alert_dicts,
            log_source=log_source,
            events_analyzed=events_analyzed,
            analysis_duration_ms=analysis_duration_ms,
            created_at=datetime.utcnow(),
        )
    
    def _generate_title(self, alerts: List[Alert], llm_analysis: LLMAnalysis) -> str:
        """Generate incident title."""
        if not alerts:
            return "Security Log Analysis - No Threats Detected"
        
        # Use LLM attack type if available
        if llm_analysis.attack_type and llm_analysis.attack_type != "Unknown":
            base_title = llm_analysis.attack_type
        else:
            # Fall back to rule names
            rule_names = list(set(a.rule_name for a in alerts))
            base_title = rule_names[0] if len(rule_names) == 1 else "Multiple Security Alerts"
        
        # Add severity indicator for high/critical
        severity = llm_analysis.severity.lower()
        if severity in ["high", "critical"]:
            return f"[{severity.upper()}] {base_title}"
        
        return base_title
    
    def _build_evidence_summary(
        self,
        alerts: List[Alert],
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build human-readable evidence summary."""
        if not alerts:
            return {
                "status": "clean",
                "message": "No security threats detected",
            }
        
        # Collect unique IPs
        all_ips = set()
        for alert in alerts:
            all_ips.update(alert.source_ips)
        
        # Collect affected users
        all_users = set()
        for alert in alerts:
            all_users.update(alert.affected_users)
        
        # Get time range
        timeline = evidence.get("timeline", {})
        
        # Severity counts
        severity_dist = evidence.get("severity_distribution", {})
        
        return {
            "total_alerts": len(alerts),
            "severity_breakdown": severity_dist,
            "source_ips": list(all_ips),
            "source_ip_count": len(all_ips),
            "affected_users": list(all_users)[:10],
            "affected_user_count": len(all_users),
            "time_range": {
                "start": timeline.get("first_event"),
                "end": timeline.get("last_event"),
                "duration_minutes": timeline.get("time_span_minutes"),
            },
            "attack_types_detected": list(set(
                indicator.get("type") 
                for indicator in evidence.get("attack_indicators", [])
            )),
        }
