"""
Suspicious IP behavior detection rule.
"""

from collections import defaultdict
from datetime import datetime
from typing import List, Set

from app.detection.rules.base import DetectionRule
from app.models.log_entry import LogEntry
from app.models.alert import Alert, Severity


class SuspiciousIPRule(DetectionRule):
    """
    Detects suspicious IP behavior patterns.
    
    Identifies IPs that:
    - Target multiple user accounts
    - Use known scanner/attack tools
    - Access sensitive paths
    - Generate high error rates
    
    MITRE ATT&CK:
    - Tactic: TA0043 (Reconnaissance)
    - Technique: T1595 (Active Scanning)
    - Tactic: TA0001 (Initial Access)
    """
    
    rule_id = "SUSPICIOUS_IP_001"
    rule_name = "Suspicious IP Behavior"
    description = "IP address exhibiting reconnaissance or attack patterns"
    mitre_tactics = ["TA0043", "TA0001"]
    mitre_techniques = ["T1595", "T1595.002", "T1190"]
    
    # Thresholds
    MULTI_USER_THRESHOLD = 3  # IPs targeting more than N users
    ERROR_RATE_THRESHOLD = 0.7  # More than 70% errors
    SUSPICIOUS_PATH_THRESHOLD = 3  # Multiple suspicious path accesses
    
    # Suspicious patterns
    SENSITIVE_PATHS = {
        '/etc/passwd', '/etc/shadow', '/.env', '/.git',
        '/wp-admin', '/phpmyadmin', '/admin', '/administrator',
        '/config', '/backup', '/.htaccess', '/web.config',
    }
    
    SCANNER_SIGNATURES = {
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab',
        'gobuster', 'dirbuster', 'wfuzz', 'hydra', 'burp',
    }
    
    def evaluate(self, entries: List[LogEntry]) -> List[Alert]:
        """Evaluate entries for suspicious IP patterns."""
        alerts = []
        
        # Group entries by IP
        ip_data = defaultdict(lambda: {
            'entries': [],
            'users': set(),
            'paths': [],
            'errors': 0,
            'total': 0,
            'suspicious_paths': set(),
            'scanner_detected': False,
            'user_agents': set(),
        })
        
        for entry in entries:
            if not entry.source_ip:
                continue
            
            ip = entry.source_ip
            data = ip_data[ip]
            data['entries'].append(entry)
            data['total'] += 1
            
            # Track users targeted
            if entry.user:
                data['users'].add(entry.user)
            
            # Track paths accessed
            if entry.resource:
                data['paths'].append(entry.resource)
                
                # Check for sensitive paths
                path_lower = entry.resource.lower()
                for sensitive in self.SENSITIVE_PATHS:
                    if sensitive in path_lower:
                        data['suspicious_paths'].add(entry.resource)
                
                # Check for path traversal
                if '..' in entry.resource:
                    data['suspicious_paths'].add(entry.resource)
            
            # Track errors
            if entry.status in {'failed', 'error', 'client_error'}:
                data['errors'] += 1
            
            # Check for scanner user agents
            user_agent = entry.metadata.get('user_agent', '')
            if user_agent:
                data['user_agents'].add(user_agent)
                ua_lower = user_agent.lower()
                if any(scanner in ua_lower for scanner in self.SCANNER_SIGNATURES):
                    data['scanner_detected'] = True
        
        # Analyze each IP
        for ip, data in ip_data.items():
            alert = self._analyze_ip(ip, data)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def _analyze_ip(self, ip: str, data: dict) -> Alert:
        """Analyze a single IP's behavior."""
        reasons = []
        severity = Severity.LOW
        
        # Check multi-user targeting
        if len(data['users']) >= self.MULTI_USER_THRESHOLD:
            reasons.append(f"Targeted {len(data['users'])} different user accounts")
            severity = max(severity, Severity.MEDIUM, key=lambda x: x.value)
        
        # Check error rate
        if data['total'] >= 10:
            error_rate = data['errors'] / data['total']
            if error_rate >= self.ERROR_RATE_THRESHOLD:
                reasons.append(f"High error rate ({int(error_rate * 100)}%)")
                severity = max(severity, Severity.MEDIUM, key=lambda x: x.value)
        
        # Check suspicious paths
        if len(data['suspicious_paths']) >= self.SUSPICIOUS_PATH_THRESHOLD:
            reasons.append(f"Accessed {len(data['suspicious_paths'])} suspicious paths")
            severity = max(severity, Severity.HIGH, key=lambda x: x.value)
        elif len(data['suspicious_paths']) > 0:
            reasons.append(f"Accessed sensitive path(s): {', '.join(list(data['suspicious_paths'])[:3])}")
            severity = max(severity, Severity.MEDIUM, key=lambda x: x.value)
        
        # Check scanner detection
        if data['scanner_detected']:
            reasons.append("Security scanner/attack tool detected")
            severity = max(severity, Severity.HIGH, key=lambda x: x.value)
        
        if not reasons:
            return None
        
        # Get time range
        timestamps = [e.timestamp for e in data['entries']]
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        
        evidence = {
            "total_requests": data['total'],
            "error_count": data['errors'],
            "error_rate_percent": int(data['errors'] / data['total'] * 100) if data['total'] > 0 else 0,
            "unique_users_targeted": len(data['users']),
            "targeted_users": list(data['users'])[:10],
            "suspicious_paths": list(data['suspicious_paths'])[:10],
            "scanner_detected": data['scanner_detected'],
            "user_agents": list(data['user_agents'])[:5],
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "detection_reasons": reasons,
        }
        
        return Alert(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=f"Suspicious activity from {ip}: {'; '.join(reasons)}",
            severity=severity,
            mitre_tactics=self.mitre_tactics,
            mitre_techniques=self.mitre_techniques,
            evidence=evidence,
            triggered_at=datetime.utcnow(),
            source_ips=[ip],
            affected_users=list(data['users']),
            log_entry_count=data['total'],
            time_window=f"{first_seen.strftime('%H:%M:%S')} - {last_seen.strftime('%H:%M:%S')} UTC",
        )
