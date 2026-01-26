"""
Evidence aggregator - structures alert data for LLM analysis.
"""

from datetime import datetime
from typing import List, Dict, Any

from app.models.log_entry import LogEntry
from app.models.alert import Alert


class EvidenceAggregator:
    """
    Aggregates and structures detection results for LLM analysis.
    
    Key responsibilities:
    1. Transform raw alerts into structured evidence
    2. Summarize patterns across multiple alerts
    3. Prepare context for LLM reasoning
    4. Ensure no raw logs are sent to LLM
    """
    
    def aggregate(
        self,
        alerts: List[Alert],
        entries: List[LogEntry],
        log_source: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Aggregate alerts and log metadata into structured evidence.
        
        Args:
            alerts: List of alerts from detection engine
            entries: Original log entries (for metadata only)
            log_source: Type of log analyzed
            
        Returns:
            Structured evidence dictionary for LLM
        """
        if not alerts:
            return self._empty_evidence(entries, log_source)
        
        # Extract time range from entries
        if entries:
            timestamps = [e.timestamp for e in entries]
            first_event = min(timestamps)
            last_event = max(timestamps)
            time_span = (last_event - first_event).total_seconds() / 60  # minutes
        else:
            first_event = last_event = datetime.utcnow()
            time_span = 0
        
        # Aggregate attack indicators
        attack_indicators = []
        for alert in alerts:
            indicator = {
                "type": self._categorize_attack(alert.rule_id),
                "rule_name": alert.rule_name,
                "severity": alert.severity.value,
                "description": alert.description,
                "source_ips": alert.source_ips,
                "affected_users": alert.affected_users[:5] if alert.affected_users else [],
                "evidence": self._summarize_evidence(alert.evidence),
                "mitre_techniques": alert.mitre_techniques,
            }
            attack_indicators.append(indicator)
        
        # Collect unique IPs and users across all alerts
        all_ips = set()
        all_users = set()
        for alert in alerts:
            all_ips.update(alert.source_ips)
            all_users.update(alert.affected_users)
        
        # Determine overall severity
        severities = [a.severity.value for a in alerts]
        if "critical" in severities:
            overall_severity = "critical"
        elif "high" in severities:
            overall_severity = "high"
        elif "medium" in severities:
            overall_severity = "medium"
        else:
            overall_severity = "low"
        
        # Collect all MITRE techniques
        mitre_techniques = set()
        for alert in alerts:
            mitre_techniques.update(alert.mitre_techniques)
        
        return {
            "analysis_summary": {
                "total_events_analyzed": len(entries),
                "alerts_generated": len(alerts),
                "overall_severity": overall_severity,
                "log_source": log_source,
                "analysis_time": datetime.utcnow().isoformat(),
            },
            "timeline": {
                "first_event": first_event.isoformat(),
                "last_event": last_event.isoformat(),
                "time_span_minutes": round(time_span, 1),
            },
            "attack_indicators": attack_indicators,
            "affected_entities": {
                "source_ips": list(all_ips),
                "source_ip_count": len(all_ips),
                "affected_users": list(all_users)[:10],
                "affected_user_count": len(all_users),
            },
            "mitre_mapping": {
                "techniques": list(mitre_techniques),
            },
            "severity_distribution": {
                "critical": sum(1 for a in alerts if a.severity.value == "critical"),
                "high": sum(1 for a in alerts if a.severity.value == "high"),
                "medium": sum(1 for a in alerts if a.severity.value == "medium"),
                "low": sum(1 for a in alerts if a.severity.value == "low"),
            },
        }
    
    def _empty_evidence(self, entries: List[LogEntry], log_source: str) -> Dict[str, Any]:
        """Return evidence structure when no alerts are generated."""
        return {
            "analysis_summary": {
                "total_events_analyzed": len(entries),
                "alerts_generated": 0,
                "overall_severity": "none",
                "log_source": log_source,
                "analysis_time": datetime.utcnow().isoformat(),
            },
            "timeline": {
                "first_event": entries[0].timestamp.isoformat() if entries else None,
                "last_event": entries[-1].timestamp.isoformat() if entries else None,
                "time_span_minutes": 0,
            },
            "attack_indicators": [],
            "affected_entities": {
                "source_ips": [],
                "source_ip_count": 0,
                "affected_users": [],
                "affected_user_count": 0,
            },
            "mitre_mapping": {
                "techniques": [],
            },
            "severity_distribution": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
        }
    
    def _categorize_attack(self, rule_id: str) -> str:
        """Categorize attack type from rule ID."""
        rule_id_lower = rule_id.lower()
        
        if "brute_force" in rule_id_lower:
            return "brute_force"
        elif "suspicious_ip" in rule_id_lower:
            return "reconnaissance"
        elif "frequency" in rule_id_lower:
            if "rate" in rule_id_lower:
                return "denial_of_service"
            elif "offhours" in rule_id_lower:
                return "suspicious_timing"
            elif "rapid" in rule_id_lower:
                return "automated_attack"
            return "anomaly"
        else:
            return "unknown"
    
    def _summarize_evidence(self, evidence: dict) -> dict:
        """
        Summarize evidence dict, removing any sensitive or verbose data.
        
        This ensures we only send high-level indicators to the LLM.
        """
        # Keys to include in summary
        summary_keys = {
            "failed_attempts", "time_window_minutes", "attempts_per_minute",
            "unique_accounts_targeted", "error_rate_percent", "total_requests",
            "peak_requests_per_minute", "off_hours_requests", "rapid_requests",
            "rapid_percentage", "likely_automated", "detection_reasons",
            "scanner_detected",
        }
        
        return {k: v for k, v in evidence.items() if k in summary_keys}
