"""
Frequency anomaly detection rule.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import List

from app.detection.rules.base import DetectionRule
from app.models.log_entry import LogEntry
from app.models.alert import Alert, Severity
from app.config import get_settings


class FrequencyAnomalyRule(DetectionRule):
    """
    Detects abnormal request frequency patterns.
    
    Identifies:
    - Request rate spikes from single IPs
    - Unusual activity during off-hours
    - Rapid sequential requests (automation indicators)
    
    MITRE ATT&CK:
    - Tactic: TA0040 (Impact)
    - Technique: T1498 (Network Denial of Service)
    - Tactic: TA0043 (Reconnaissance)
    """
    
    rule_id = "FREQUENCY_ANOMALY_001"
    rule_name = "Abnormal Request Frequency"
    description = "Unusual rate of requests detected"
    mitre_tactics = ["TA0040", "TA0043"]
    mitre_techniques = ["T1498", "T1595"]
    
    # Off-hours definition (UTC)
    OFF_HOURS_START = 22  # 10 PM
    OFF_HOURS_END = 6     # 6 AM
    
    def __init__(self):
        settings = get_settings()
        self.threshold_per_minute = settings.frequency_threshold_per_minute
    
    def evaluate(self, entries: List[LogEntry]) -> List[Alert]:
        """Evaluate entries for frequency anomalies."""
        alerts = []
        
        if not entries:
            return alerts
        
        # Group by IP
        ip_entries = defaultdict(list)
        for entry in entries:
            if entry.source_ip:
                ip_entries[entry.source_ip].append(entry)
        
        # Analyze each IP
        for ip, ip_logs in ip_entries.items():
            # Sort by timestamp
            ip_logs.sort(key=lambda x: x.timestamp)
            
            # Check rate per minute
            rate_alert = self._check_rate(ip, ip_logs)
            if rate_alert:
                alerts.append(rate_alert)
            
            # Check off-hours activity
            offhours_alert = self._check_off_hours(ip, ip_logs)
            if offhours_alert:
                alerts.append(offhours_alert)
            
            # Check rapid sequential requests
            rapid_alert = self._check_rapid_requests(ip, ip_logs)
            if rapid_alert:
                alerts.append(rapid_alert)
        
        return alerts
    
    def _check_rate(self, ip: str, entries: List[LogEntry]) -> Alert:
        """Check for high request rate."""
        if len(entries) < 10:
            return None
        
        # Group by minute
        minute_counts = defaultdict(int)
        for entry in entries:
            minute_key = entry.timestamp.strftime("%Y-%m-%d %H:%M")
            minute_counts[minute_key] += 1
        
        # Find peak minute
        if not minute_counts:
            return None
        
        peak_minute = max(minute_counts, key=minute_counts.get)
        peak_count = minute_counts[peak_minute]
        avg_count = sum(minute_counts.values()) / len(minute_counts)
        
        if peak_count < self.threshold_per_minute:
            return None
        
        # Determine severity
        if peak_count >= self.threshold_per_minute * 5:
            severity = Severity.CRITICAL
        elif peak_count >= self.threshold_per_minute * 2:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        
        first_seen = min(e.timestamp for e in entries)
        last_seen = max(e.timestamp for e in entries)
        
        evidence = {
            "peak_requests_per_minute": peak_count,
            "peak_minute": peak_minute,
            "average_requests_per_minute": round(avg_count, 1),
            "threshold": self.threshold_per_minute,
            "total_requests": len(entries),
            "time_span_minutes": len(minute_counts),
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
        }
        
        return Alert(
            rule_id=f"{self.rule_id}_RATE",
            rule_name=f"{self.rule_name} - High Rate",
            description=f"IP {ip} generated {peak_count} requests/minute (threshold: {self.threshold_per_minute})",
            severity=severity,
            mitre_tactics=["TA0040"],
            mitre_techniques=["T1498"],
            evidence=evidence,
            triggered_at=datetime.utcnow(),
            source_ips=[ip],
            log_entry_count=len(entries),
            time_window=f"{first_seen.strftime('%H:%M:%S')} - {last_seen.strftime('%H:%M:%S')} UTC",
        )
    
    def _check_off_hours(self, ip: str, entries: List[LogEntry]) -> Alert:
        """Check for significant off-hours activity."""
        off_hours_entries = [
            e for e in entries
            if e.timestamp.hour >= self.OFF_HOURS_START or e.timestamp.hour < self.OFF_HOURS_END
        ]
        
        # Need significant off-hours activity
        if len(off_hours_entries) < 20:
            return None
        
        # Check if mostly off-hours
        off_hours_ratio = len(off_hours_entries) / len(entries)
        if off_hours_ratio < 0.7:  # Less than 70% off-hours
            return None
        
        first_seen = min(e.timestamp for e in off_hours_entries)
        last_seen = max(e.timestamp for e in off_hours_entries)
        
        # Check for suspicious actions during off-hours
        suspicious_actions = [
            e for e in off_hours_entries
            if e.action in {'login_failed', 'suspicious_request', 'unauthorized_access'}
        ]
        
        severity = Severity.MEDIUM
        if len(suspicious_actions) > 10:
            severity = Severity.HIGH
        
        evidence = {
            "off_hours_requests": len(off_hours_entries),
            "total_requests": len(entries),
            "off_hours_percentage": int(off_hours_ratio * 100),
            "suspicious_actions_count": len(suspicious_actions),
            "off_hours_definition": f"{self.OFF_HOURS_START}:00 - {self.OFF_HOURS_END}:00 UTC",
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
        }
        
        return Alert(
            rule_id=f"{self.rule_id}_OFFHOURS",
            rule_name=f"{self.rule_name} - Off-Hours Activity",
            description=f"IP {ip} showed {len(off_hours_entries)} requests during off-hours ({int(off_hours_ratio * 100)}% of activity)",
            severity=severity,
            mitre_tactics=["TA0043"],
            mitre_techniques=["T1595"],
            evidence=evidence,
            triggered_at=datetime.utcnow(),
            source_ips=[ip],
            log_entry_count=len(off_hours_entries),
            time_window=f"{first_seen.strftime('%H:%M:%S')} - {last_seen.strftime('%H:%M:%S')} UTC",
        )
    
    def _check_rapid_requests(self, ip: str, entries: List[LogEntry]) -> Alert:
        """Check for rapid sequential requests (automation indicator)."""
        if len(entries) < 20:
            return None
        
        # Calculate time gaps between requests
        gaps = []
        for i in range(1, len(entries)):
            gap = (entries[i].timestamp - entries[i-1].timestamp).total_seconds()
            gaps.append(gap)
        
        if not gaps:
            return None
        
        # Check for very consistent timing (automation signature)
        avg_gap = sum(gaps) / len(gaps)
        
        # Count rapid requests (less than 1 second apart)
        rapid_count = sum(1 for g in gaps if g < 1.0)
        rapid_ratio = rapid_count / len(gaps)
        
        if rapid_ratio < 0.5:  # Less than 50% rapid
            return None
        
        # Calculate standard deviation of gaps (low = automated)
        if len(gaps) > 1:
            variance = sum((g - avg_gap) ** 2 for g in gaps) / len(gaps)
            std_dev = variance ** 0.5
        else:
            std_dev = 0
        
        is_automated = avg_gap < 1.0 and std_dev < 0.5
        
        severity = Severity.MEDIUM
        if is_automated and rapid_count > 100:
            severity = Severity.HIGH
        
        first_seen = entries[0].timestamp
        last_seen = entries[-1].timestamp
        
        evidence = {
            "total_requests": len(entries),
            "rapid_requests": rapid_count,
            "rapid_percentage": int(rapid_ratio * 100),
            "average_gap_seconds": round(avg_gap, 3),
            "gap_std_deviation": round(std_dev, 3),
            "likely_automated": is_automated,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
        }
        
        return Alert(
            rule_id=f"{self.rule_id}_RAPID",
            rule_name=f"{self.rule_name} - Rapid Requests",
            description=f"IP {ip} made {rapid_count} rapid requests ({int(rapid_ratio * 100)}% under 1s apart). {'Likely automated.' if is_automated else ''}",
            severity=severity,
            mitre_tactics=["TA0043"],
            mitre_techniques=["T1595"],
            evidence=evidence,
            triggered_at=datetime.utcnow(),
            source_ips=[ip],
            log_entry_count=len(entries),
            time_window=f"{first_seen.strftime('%H:%M:%S')} - {last_seen.strftime('%H:%M:%S')} UTC",
        )
