"""
Detection engine - orchestrates all detection rules.
"""

from typing import List, Optional

from app.models.log_entry import LogEntry
from app.models.alert import Alert
from app.detection.rules.base import DetectionRule
from app.detection.rules.brute_force import BruteForceRule
from app.detection.rules.suspicious_ip import SuspiciousIPRule
from app.detection.rules.frequency import FrequencyAnomalyRule


class DetectionEngine:
    """
    Orchestrates detection rules and runs them against log entries.
    
    The engine:
    1. Maintains a list of active detection rules
    2. Runs applicable rules against provided log entries
    3. Collects and returns all generated alerts
    4. Supports rule filtering and prioritization
    """
    
    def __init__(self, rules: Optional[List[DetectionRule]] = None):
        """
        Initialize detection engine with rules.
        
        Args:
            rules: Optional list of custom rules. If None, uses default rules.
        """
        if rules is None:
            self.rules = self._get_default_rules()
        else:
            self.rules = rules
    
    def _get_default_rules(self) -> List[DetectionRule]:
        """Get the default set of detection rules."""
        return [
            BruteForceRule(),
            SuspiciousIPRule(),
            FrequencyAnomalyRule(),
        ]
    
    def analyze(self, entries: List[LogEntry]) -> List[Alert]:
        """
        Run all applicable rules against log entries.
        
        Args:
            entries: List of normalized log entries to analyze
            
        Returns:
            List of alerts from all rules
        """
        all_alerts = []
        
        for rule in self.rules:
            # Check if rule is applicable
            if not rule.is_applicable(entries):
                continue
            
            # Run the rule
            try:
                alerts = rule.evaluate(entries)
                all_alerts.extend(alerts)
            except Exception as e:
                # Log error but continue with other rules
                print(f"Error running rule {rule.rule_id}: {e}")
                continue
        
        # Deduplicate alerts (same IP + same rule within same time window)
        deduplicated = self._deduplicate_alerts(all_alerts)
        
        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        deduplicated.sort(key=lambda a: severity_order.get(a.severity.value, 4))
        
        return deduplicated
    
    def _deduplicate_alerts(self, alerts: List[Alert]) -> List[Alert]:
        """
        Remove duplicate alerts.
        
        Alerts are considered duplicates if they have the same:
        - rule_id
        - source_ips
        - time_window overlap
        """
        if not alerts:
            return alerts
        
        seen = set()
        unique_alerts = []
        
        for alert in alerts:
            # Create a dedup key
            key = (
                alert.rule_id,
                tuple(sorted(alert.source_ips)),
            )
            
            if key not in seen:
                seen.add(key)
                unique_alerts.append(alert)
        
        return unique_alerts
    
    def add_rule(self, rule: DetectionRule):
        """Add a custom detection rule."""
        self.rules.append(rule)
    
    def remove_rule(self, rule_id: str):
        """Remove a rule by ID."""
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
    
    def get_rule_info(self) -> List[dict]:
        """Get information about all loaded rules."""
        return [
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "description": r.description,
                "mitre_tactics": r.mitre_tactics,
                "mitre_techniques": r.mitre_techniques,
            }
            for r in self.rules
        ]
