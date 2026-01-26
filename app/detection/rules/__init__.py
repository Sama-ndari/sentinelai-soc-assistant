"""
Detection rules module.
"""

from app.detection.rules.base import DetectionRule
from app.detection.rules.brute_force import BruteForceRule
from app.detection.rules.suspicious_ip import SuspiciousIPRule
from app.detection.rules.frequency import FrequencyAnomalyRule

__all__ = [
    "DetectionRule",
    "BruteForceRule",
    "SuspiciousIPRule",
    "FrequencyAnomalyRule",
]
