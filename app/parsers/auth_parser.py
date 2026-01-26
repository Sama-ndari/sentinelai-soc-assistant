"""
Parser for Linux auth/syslog format (auth.log, secure, messages).
"""

import re
from datetime import datetime
from typing import Optional

from app.parsers.base import BaseParser
from app.models.log_entry import LogEntry, LogType


class AuthLogParser(BaseParser):
    """
    Parser for Linux authentication logs.
    
    Handles formats like:
    - auth.log (Debian/Ubuntu)
    - secure (RHEL/CentOS)
    - SSH authentication events
    - sudo events
    - PAM events
    """
    
    log_type = LogType.AUTH
    
    # Regex patterns for different auth log formats
    PATTERNS = {
        # SSH failed password: Jan 15 03:22:15 server sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2
        "ssh_failed": re.compile(
            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+"
            r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
        ),
        # SSH accepted password
        "ssh_accepted": re.compile(
            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+"
            r"Accepted (\S+) for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
        ),
        # SSH invalid user
        "ssh_invalid_user": re.compile(
            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+"
            r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)"
        ),
        # sudo authentication failure
        "sudo_failure": re.compile(
            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sudo\S*:\s+"
            r".*authentication failure.*user=(\S+)"
        ),
        # Generic auth failure
        "auth_failure": re.compile(
            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+\S+:\s+"
            r".*(?:authentication failure|auth.*fail).*"
        ),
    }
    
    def can_parse(self, line: str) -> bool:
        """Check if line matches auth log format."""
        # Quick check for syslog-style timestamp
        if not re.match(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", line):
            return False
        
        # Check for auth-related keywords
        auth_keywords = ["sshd", "sudo", "su:", "login", "pam", "authentication"]
        return any(kw in line.lower() for kw in auth_keywords)
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single auth log line."""
        line = line.strip()
        if not line:
            return None
        
        # Try SSH failed password
        match = self.PATTERNS["ssh_failed"].match(line)
        if match:
            timestamp_str, hostname, pid, user, ip, port = match.groups()
            return LogEntry(
                timestamp=self._parse_timestamp(timestamp_str),
                source_ip=ip,
                user=user,
                action="login_failed",
                resource="sshd",
                status="failed",
                raw_line=line,
                log_type=self.log_type,
                metadata={
                    "hostname": hostname,
                    "pid": int(pid),
                    "port": int(port),
                    "service": "ssh",
                    "auth_method": "password",
                }
            )
        
        # Try SSH accepted password
        match = self.PATTERNS["ssh_accepted"].match(line)
        if match:
            timestamp_str, hostname, pid, auth_method, user, ip, port = match.groups()
            return LogEntry(
                timestamp=self._parse_timestamp(timestamp_str),
                source_ip=ip,
                user=user,
                action="login_success",
                resource="sshd",
                status="success",
                raw_line=line,
                log_type=self.log_type,
                metadata={
                    "hostname": hostname,
                    "pid": int(pid),
                    "port": int(port),
                    "service": "ssh",
                    "auth_method": auth_method,
                }
            )
        
        # Try SSH invalid user
        match = self.PATTERNS["ssh_invalid_user"].match(line)
        if match:
            timestamp_str, hostname, pid, user, ip = match.groups()
            return LogEntry(
                timestamp=self._parse_timestamp(timestamp_str),
                source_ip=ip,
                user=user,
                action="invalid_user",
                resource="sshd",
                status="failed",
                raw_line=line,
                log_type=self.log_type,
                metadata={
                    "hostname": hostname,
                    "pid": int(pid),
                    "service": "ssh",
                }
            )
        
        # Try sudo failure
        match = self.PATTERNS["sudo_failure"].match(line)
        if match:
            timestamp_str, hostname, user = match.groups()
            return LogEntry(
                timestamp=self._parse_timestamp(timestamp_str),
                source_ip=None,
                user=user,
                action="sudo_failure",
                resource="sudo",
                status="failed",
                raw_line=line,
                log_type=self.log_type,
                metadata={
                    "hostname": hostname,
                    "service": "sudo",
                }
            )
        
        # Generic auth failure fallback
        match = self.PATTERNS["auth_failure"].match(line)
        if match:
            timestamp_str, hostname = match.groups()[:2]
            return LogEntry(
                timestamp=self._parse_timestamp(timestamp_str),
                source_ip=None,
                user=None,
                action="auth_failure",
                resource="auth",
                status="failed",
                raw_line=line,
                log_type=self.log_type,
                metadata={
                    "hostname": hostname,
                }
            )
        
        return None
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse syslog timestamp format.
        
        Syslog timestamps don't include year, so we assume current year.
        """
        current_year = datetime.now().year
        try:
            # Parse "Jan 15 03:22:15" format
            dt = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            return dt
        except ValueError:
            # Return current time as fallback
            return datetime.now()
