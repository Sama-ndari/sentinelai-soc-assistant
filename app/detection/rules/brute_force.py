"""
Brute force attack detection rule.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import List

from app.detection.rules.base import DetectionRule
from app.models.log_entry import LogEntry, LogType
from app.models.alert import Alert, Severity
from app.config import get_settings


class BruteForceRule(DetectionRule):
    """
    Detects brute force login attempts.
    
    Triggers when multiple failed login attempts are detected
    from the same source IP within a configurable time window.
    
    MITRE ATT&CK:
    - Tactic: TA0006 (Credential Access)
    - Technique: T1110 (Brute Force)
    - Sub-technique: T1110.001 (Password Guessing)
    """
    
    rule_id = "BRUTE_FORCE_001"
    rule_name = "Brute Force Login Attack"
    description = "Multiple failed authentication attempts from single source"
    mitre_tactics = ["TA0006"]
    mitre_techniques = ["T1110", "T1110.001"]
    
    def __init__(self):
        settings = get_settings()
        self.threshold = settings.brute_force_threshold
        self.window_minutes = settings.brute_force_window_minutes
    
    def is_applicable(self, entries: List[LogEntry]) -> bool:
        """Check if entries contain authentication events."""
        auth_actions = {"login_failed", "auth_failure", "invalid_user", "unauthorized_access"}
        return any(e.action in auth_actions for e in entries)
    
    def evaluate(self, entries: List[LogEntry]) -> List[Alert]:
        """
        Evaluate entries for brute force patterns.
        
        Groups failed logins by source IP and checks if any IP
        exceeds the threshold within the time window.
        """
        alerts = []
        
        # Filter to failed login attempts
        failed_logins = [
            e for e in entries 
            if e.action in {"login_failed", "auth_failure", "invalid_user", "unauthorized_access"}
            and e.source_ip
        ]
        
        if not failed_logins:
            return alerts
        
        # Group by source IP
        ip_attempts = defaultdict(list)
        for entry in failed_logins:
            ip_attempts[entry.source_ip].append(entry)
        
        # Check each IP for brute force pattern
        for ip, attempts in ip_attempts.items():
            # Sort by timestamp
            attempts.sort(key=lambda x: x.timestamp)
            
            # Sliding window analysis
            window_alerts = self._analyze_window(ip, attempts)
            alerts.extend(window_alerts)
        
        return alerts
    
    def _analyze_window(self, ip: str, attempts: List[LogEntry]) -> List[Alert]:
        """Analyze attempts within sliding time windows."""
        alerts = []
        window = timedelta(minutes=self.window_minutes)
        
        # Use sliding window to find clusters of attempts
        i = 0
        while i < len(attempts):
            window_start = attempts[i].timestamp
            window_end = window_start + window
            
            # Find all attempts within this window
            window_attempts = [
                a for a in attempts[i:]
                if a.timestamp <= window_end
            ]
            
            if len(window_attempts) >= self.threshold:
                # Brute force detected
                alert = self._create_alert(ip, window_attempts)
                alerts.append(alert)
                
                # Skip past this window to avoid duplicate alerts
                i += len(window_attempts)
            else:
                i += 1
        
        return alerts
    
    def _create_alert(self, ip: str, attempts: List[LogEntry]) -> Alert:
        """Create alert from detected brute force attempts."""
        # Collect affected users
        users = list(set(a.user for a in attempts if a.user))
        
        # Determine severity based on attempt count
        count = len(attempts)
        if count >= 50:
            severity = Severity.CRITICAL
        elif count >= 20:
            severity = Severity.HIGH
        elif count >= 10:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        # Calculate time window
        first_attempt = min(a.timestamp for a in attempts)
        last_attempt = max(a.timestamp for a in attempts)
        duration_seconds = (last_attempt - first_attempt).total_seconds()
        
        # Build evidence
        evidence = {
            "failed_attempts": count,
            "time_window_seconds": int(duration_seconds),
            "time_window_minutes": round(duration_seconds / 60, 1),
            "attempts_per_minute": round(count / max(duration_seconds / 60, 1), 1),
            "targeted_accounts": users[:10],  # Limit for readability
            "first_attempt": first_attempt.isoformat(),
            "last_attempt": last_attempt.isoformat(),
            "unique_accounts_targeted": len(users),
        }
        
        # Check for successful login after failed attempts (account compromise)
        # This would need additional context from success logs
        
        return Alert(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=f"Detected {count} failed login attempts from {ip} targeting {len(users)} account(s) over {round(duration_seconds / 60, 1)} minutes",
            severity=severity,
            mitre_tactics=self.mitre_tactics,
            mitre_techniques=self.mitre_techniques,
            evidence=evidence,
            triggered_at=datetime.utcnow(),
            source_ips=[ip],
            affected_users=users,
            log_entry_count=count,
            time_window=f"{first_attempt.strftime('%H:%M:%S')} - {last_attempt.strftime('%H:%M:%S')} UTC",
        )
