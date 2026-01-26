"""
Abstract base class for detection rules.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from app.models.log_entry import LogEntry
from app.models.alert import Alert


class DetectionRule(ABC):
    """
    Abstract base class for all detection rules.
    
    Each rule must define:
    - rule_id: Unique identifier
    - rule_name: Human-readable name
    - description: What the rule detects
    - mitre_tactics: Related MITRE ATT&CK tactics
    - mitre_techniques: Related MITRE ATT&CK techniques
    - evaluate(): Core detection logic
    """
    
    rule_id: str
    rule_name: str
    description: str
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []
    
    @abstractmethod
    def evaluate(self, entries: List[LogEntry]) -> List[Alert]:
        """
        Evaluate log entries against this rule.
        
        Args:
            entries: List of normalized log entries
            
        Returns:
            List of alerts if rule conditions are met, empty list otherwise
        """
        pass
    
    def is_applicable(self, entries: List[LogEntry]) -> bool:
        """
        Check if this rule is applicable to the given log entries.
        
        Override this method to filter rules based on log type
        or other characteristics.
        
        Args:
            entries: List of log entries to check
            
        Returns:
            True if rule should be evaluated against these entries
        """
        return len(entries) > 0
