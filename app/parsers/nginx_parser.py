"""
Parser for Nginx access logs.
"""

import re
from datetime import datetime
from typing import Optional

from app.parsers.base import BaseParser
from app.models.log_entry import LogEntry, LogType


class NginxLogParser(BaseParser):
    """
    Parser for Nginx combined log format.
    
    Format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
    Example: 192.168.1.50 - - [15/Jan/2024:04:15:22 +0000] "GET /admin HTTP/1.1" 404 0 "-" "Mozilla/5.0"
    """
    
    log_type = LogType.NGINX
    
    # Nginx combined log format regex
    NGINX_PATTERN = re.compile(
        r'^(\d+\.\d+\.\d+\.\d+)\s+'          # IP address
        r'-\s+'                               # - 
        r'(\S+)\s+'                           # remote user (usually -)
        r'\[([^\]]+)\]\s+'                    # timestamp [15/Jan/2024:04:15:22 +0000]
        r'"(\S+)\s+(\S+)\s+(\S+)"\s+'         # "METHOD PATH PROTOCOL"
        r'(\d+)\s+'                           # status code
        r'(\d+)\s+'                           # bytes sent
        r'"([^"]*)"\s+'                       # referer
        r'"([^"]*)"'                          # user agent
    )
    
    # Patterns that indicate suspicious activity
    SUSPICIOUS_PATHS = [
        r'\.\./',                    # Path traversal
        r'/etc/passwd',
        r'/etc/shadow',
        r'/proc/',
        r'\.env',
        r'wp-admin',
        r'wp-login',
        r'phpmyadmin',
        r'/admin',
        r'\.git',
        r'\.htaccess',
        r'shell',
        r'cmd=',
        r'exec=',
    ]
    
    SCANNER_USER_AGENTS = [
        'sqlmap',
        'nikto',
        'nmap',
        'masscan',
        'zgrab',
        'gobuster',
        'dirbuster',
        'wfuzz',
        'hydra',
    ]
    
    def can_parse(self, line: str) -> bool:
        """Check if line matches nginx log format."""
        return bool(self.NGINX_PATTERN.match(line.strip()))
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single nginx log line."""
        line = line.strip()
        if not line:
            return None
        
        match = self.NGINX_PATTERN.match(line)
        if not match:
            return None
        
        (ip, remote_user, timestamp_str, method, path, protocol,
         status, bytes_sent, referer, user_agent) = match.groups()
        
        # Determine action based on status code and path
        status_code = int(status)
        action = self._determine_action(method, path, status_code, user_agent)
        
        # Determine status category
        status_category = self._categorize_status(status_code)
        
        return LogEntry(
            timestamp=self._parse_timestamp(timestamp_str),
            source_ip=ip,
            user=remote_user if remote_user != "-" else None,
            action=action,
            resource=path,
            status=status_category,
            raw_line=line,
            log_type=self.log_type,
            metadata={
                "method": method,
                "path": path,
                "protocol": protocol,
                "status_code": status_code,
                "bytes_sent": int(bytes_sent),
                "referer": referer if referer != "-" else None,
                "user_agent": user_agent,
                "is_suspicious": self._is_suspicious(path, user_agent),
                "is_scanner": self._is_scanner(user_agent),
            }
        )
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse nginx timestamp format: 15/Jan/2024:04:15:22 +0000"""
        try:
            # Remove timezone for simpler parsing
            timestamp_clean = timestamp_str.split()[0] if ' ' in timestamp_str else timestamp_str
            return datetime.strptime(timestamp_clean, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return datetime.now()
    
    def _determine_action(self, method: str, path: str, status: int, user_agent: str) -> str:
        """Determine the action type based on request characteristics."""
        # Check for scanning activity
        if self._is_scanner(user_agent):
            return "scanner_request"
        
        # Check for path traversal
        if '..' in path or any(re.search(p, path.lower()) for p in self.SUSPICIOUS_PATHS):
            return "suspicious_request"
        
        # Status-based classification
        if status >= 500:
            return "server_error"
        elif status == 403:
            return "forbidden_access"
        elif status == 401:
            return "unauthorized_access"
        elif status == 404:
            return "not_found"
        elif status >= 400:
            return "client_error"
        elif status >= 300:
            return "redirect"
        else:
            return "request"
    
    def _categorize_status(self, status: int) -> str:
        """Categorize HTTP status code."""
        if status >= 500:
            return "error"
        elif status >= 400:
            return "client_error"
        elif status >= 300:
            return "redirect"
        elif status >= 200:
            return "success"
        else:
            return "info"
    
    def _is_suspicious(self, path: str, user_agent: str) -> bool:
        """Check if request appears suspicious."""
        path_lower = path.lower()
        ua_lower = user_agent.lower()
        
        # Check suspicious paths
        for pattern in self.SUSPICIOUS_PATHS:
            if re.search(pattern, path_lower):
                return True
        
        # Check scanner user agents
        if self._is_scanner(user_agent):
            return True
        
        return False
    
    def _is_scanner(self, user_agent: str) -> bool:
        """Check if user agent indicates a security scanner."""
        ua_lower = user_agent.lower()
        return any(scanner in ua_lower for scanner in self.SCANNER_USER_AGENTS)
