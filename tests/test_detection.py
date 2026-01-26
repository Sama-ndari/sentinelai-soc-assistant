"""
Tests for detection engine and rules.
"""

import pytest
from datetime import datetime, timedelta

from app.models.log_entry import LogEntry, LogType
from app.models.alert import Severity
from app.detection.engine import DetectionEngine
from app.detection.rules.brute_force import BruteForceRule
from app.detection.rules.suspicious_ip import SuspiciousIPRule
from app.detection.aggregator import EvidenceAggregator


def create_failed_login(ip: str, user: str, timestamp: datetime) -> LogEntry:
    """Helper to create a failed login log entry."""
    return LogEntry(
        timestamp=timestamp,
        source_ip=ip,
        user=user,
        action="login_failed",
        resource="sshd",
        status="failed",
        raw_line=f"sshd: Failed password for {user} from {ip}",
        log_type=LogType.AUTH,
        metadata={"service": "ssh"},
    )


def create_nginx_request(ip: str, path: str, status: int, user_agent: str, timestamp: datetime) -> LogEntry:
    """Helper to create a nginx log entry."""
    is_scanner = any(s in user_agent.lower() for s in ["sqlmap", "nikto", "nmap"])
    is_suspicious = ".." in path or any(p in path.lower() for p in ["/etc/", "/.env", "/.git"])
    
    action = "request"
    if is_scanner:
        action = "scanner_request"
    elif is_suspicious:
        action = "suspicious_request"
    elif status >= 400:
        action = "client_error"
    
    return LogEntry(
        timestamp=timestamp,
        source_ip=ip,
        user=None,
        action=action,
        resource=path,
        status="error" if status >= 400 else "success",
        raw_line=f'{ip} - - "GET {path}" {status}',
        log_type=LogType.NGINX,
        metadata={
            "status_code": status,
            "user_agent": user_agent,
            "is_scanner": is_scanner,
            "is_suspicious": is_suspicious,
        },
    )


class TestBruteForceRule:
    """Tests for BruteForceRule."""
    
    def setup_method(self):
        self.rule = BruteForceRule()
    
    def test_no_alerts_below_threshold(self):
        """Should not alert with fewer than threshold failed logins."""
        base_time = datetime.now()
        entries = [
            create_failed_login("192.168.1.100", "admin", base_time + timedelta(seconds=i))
            for i in range(4)  # Only 4 attempts, threshold is 5
        ]
        
        alerts = self.rule.evaluate(entries)
        assert len(alerts) == 0
    
    def test_alerts_at_threshold(self):
        """Should alert when threshold is reached."""
        base_time = datetime.now()
        entries = [
            create_failed_login("192.168.1.100", "admin", base_time + timedelta(seconds=i * 2))
            for i in range(10)  # 10 attempts
        ]
        
        alerts = self.rule.evaluate(entries)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "BRUTE_FORCE_001"
        assert "192.168.1.100" in alerts[0].source_ips
    
    def test_severity_escalation(self):
        """Severity should increase with more attempts."""
        base_time = datetime.now()
        
        # 10 attempts = MEDIUM
        entries_medium = [
            create_failed_login("192.168.1.100", "admin", base_time + timedelta(seconds=i))
            for i in range(10)
        ]
        alerts_medium = self.rule.evaluate(entries_medium)
        assert alerts_medium[0].severity == Severity.MEDIUM
        
        # 25 attempts = HIGH
        entries_high = [
            create_failed_login("192.168.1.100", "admin", base_time + timedelta(seconds=i))
            for i in range(25)
        ]
        alerts_high = self.rule.evaluate(entries_high)
        assert alerts_high[0].severity == Severity.HIGH
    
    def test_multiple_ips_separate_alerts(self):
        """Different source IPs should generate separate alerts."""
        base_time = datetime.now()
        entries = []
        
        for ip in ["192.168.1.100", "192.168.1.101"]:
            for i in range(10):
                entries.append(create_failed_login(ip, "admin", base_time + timedelta(seconds=i)))
        
        alerts = self.rule.evaluate(entries)
        assert len(alerts) == 2
        
        alert_ips = [a.source_ips[0] for a in alerts]
        assert "192.168.1.100" in alert_ips
        assert "192.168.1.101" in alert_ips


class TestSuspiciousIPRule:
    """Tests for SuspiciousIPRule."""
    
    def setup_method(self):
        self.rule = SuspiciousIPRule()
    
    def test_detect_scanner(self):
        """Should detect security scanner user agents."""
        base_time = datetime.now()
        entries = [
            create_nginx_request("192.168.1.50", f"/page{i}", 200, "sqlmap/1.4", base_time + timedelta(seconds=i))
            for i in range(5)
        ]
        
        alerts = self.rule.evaluate(entries)
        assert len(alerts) == 1
        assert alerts[0].evidence.get("scanner_detected") is True
    
    def test_detect_suspicious_paths(self):
        """Should detect access to suspicious paths."""
        base_time = datetime.now()
        suspicious_paths = ["/.env", "/.git/config", "/../../etc/passwd", "/wp-admin"]
        
        entries = [
            create_nginx_request("192.168.1.50", path, 404, "Mozilla/5.0", base_time + timedelta(seconds=i))
            for i, path in enumerate(suspicious_paths)
        ]
        
        alerts = self.rule.evaluate(entries)
        assert len(alerts) == 1
        assert len(alerts[0].evidence.get("suspicious_paths", [])) >= 3


class TestDetectionEngine:
    """Tests for DetectionEngine."""
    
    def setup_method(self):
        self.engine = DetectionEngine()
    
    def test_runs_all_rules(self):
        """Engine should run all applicable rules."""
        base_time = datetime.now()
        
        # Create entries that should trigger brute force
        entries = [
            create_failed_login("192.168.1.100", "admin", base_time + timedelta(seconds=i))
            for i in range(15)
        ]
        
        alerts = self.engine.analyze(entries)
        
        # Should have at least one alert
        assert len(alerts) >= 1
        
        # Check that brute force was detected
        rule_ids = [a.rule_id for a in alerts]
        assert "BRUTE_FORCE_001" in rule_ids
    
    def test_deduplication(self):
        """Engine should deduplicate alerts."""
        base_time = datetime.now()
        entries = [
            create_failed_login("192.168.1.100", "admin", base_time + timedelta(seconds=i))
            for i in range(10)
        ]
        
        alerts = self.engine.analyze(entries)
        
        # Should not have duplicate alerts for same IP/rule
        seen = set()
        for alert in alerts:
            key = (alert.rule_id, tuple(sorted(alert.source_ips)))
            assert key not in seen, f"Duplicate alert: {key}"
            seen.add(key)


class TestEvidenceAggregator:
    """Tests for EvidenceAggregator."""
    
    def setup_method(self):
        self.aggregator = EvidenceAggregator()
    
    def test_aggregate_empty_alerts(self):
        """Should handle empty alert list."""
        entries = [
            LogEntry(
                timestamp=datetime.now(),
                source_ip="10.0.0.1",
                user="user",
                action="login_success",
                resource="sshd",
                status="success",
                raw_line="test",
                log_type=LogType.AUTH,
            )
        ]
        
        evidence = self.aggregator.aggregate([], entries, "auth")
        
        assert evidence["analysis_summary"]["alerts_generated"] == 0
        assert evidence["analysis_summary"]["overall_severity"] == "none"
    
    def test_aggregate_with_alerts(self):
        """Should properly aggregate alerts."""
        from app.models.alert import Alert, Severity
        
        alerts = [
            Alert(
                rule_id="TEST_001",
                rule_name="Test Rule",
                description="Test alert",
                severity=Severity.HIGH,
                evidence={"failed_attempts": 10},
                source_ips=["192.168.1.100"],
                affected_users=["admin", "root"],
                mitre_techniques=["T1110"],
            )
        ]
        
        entries = [
            LogEntry(
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                user="admin",
                action="login_failed",
                resource="sshd",
                status="failed",
                raw_line="test",
                log_type=LogType.AUTH,
            )
        ]
        
        evidence = self.aggregator.aggregate(alerts, entries, "auth")
        
        assert evidence["analysis_summary"]["alerts_generated"] == 1
        assert evidence["analysis_summary"]["overall_severity"] == "high"
        assert "192.168.1.100" in evidence["affected_entities"]["source_ips"]
        assert "T1110" in evidence["mitre_mapping"]["techniques"]
