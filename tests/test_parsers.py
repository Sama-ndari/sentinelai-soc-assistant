"""
Tests for log parsers.
"""

import pytest
from datetime import datetime

from app.parsers.auth_parser import AuthLogParser
from app.parsers.nginx_parser import NginxLogParser
from app.parsers.json_parser import JSONLogParser
from app.parsers.base import ParserOrchestrator
from app.models.log_entry import LogType


class TestAuthLogParser:
    """Tests for AuthLogParser."""
    
    def setup_method(self):
        self.parser = AuthLogParser()
    
    def test_can_parse_ssh_failed(self):
        line = "Jan 15 03:22:15 server sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2"
        assert self.parser.can_parse(line) is True
    
    def test_can_parse_non_auth(self):
        line = "192.168.1.50 - - [15/Jan/2024:04:15:22 +0000] \"GET / HTTP/1.1\" 200 1234"
        assert self.parser.can_parse(line) is False
    
    def test_parse_ssh_failed_password(self):
        line = "Jan 15 03:22:15 server sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2"
        entry = self.parser.parse_line(line)
        
        assert entry is not None
        assert entry.source_ip == "192.168.1.100"
        assert entry.user == "admin"
        assert entry.action == "login_failed"
        assert entry.log_type == LogType.AUTH
        assert entry.metadata["port"] == 54321
    
    def test_parse_ssh_accepted(self):
        line = "Jan 15 03:27:42 server sshd[12390]: Accepted password for admin from 192.168.1.100 port 54365 ssh2"
        entry = self.parser.parse_line(line)
        
        assert entry is not None
        assert entry.action == "login_success"
        assert entry.status == "success"
    
    def test_parse_invalid_user(self):
        line = "Jan 15 03:22:41 server sshd[12358]: Invalid user oracle from 192.168.1.100 port 54334 ssh2"
        entry = self.parser.parse_line(line)
        
        assert entry is not None
        assert entry.action == "invalid_user"
        assert entry.user == "oracle"


class TestNginxLogParser:
    """Tests for NginxLogParser."""
    
    def setup_method(self):
        self.parser = NginxLogParser()
    
    def test_can_parse_nginx(self):
        line = '192.168.1.50 - - [15/Jan/2024:04:15:22 +0000] "GET /admin HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        assert self.parser.can_parse(line) is True
    
    def test_can_parse_non_nginx(self):
        line = "Jan 15 03:22:15 server sshd[12345]: Failed password for admin"
        assert self.parser.can_parse(line) is False
    
    def test_parse_nginx_request(self):
        line = '192.168.1.50 - - [15/Jan/2024:04:15:22 +0000] "GET /admin HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        entry = self.parser.parse_line(line)
        
        assert entry is not None
        assert entry.source_ip == "192.168.1.50"
        assert entry.resource == "/admin"
        assert entry.log_type == LogType.NGINX
        assert entry.metadata["status_code"] == 404
        assert entry.metadata["method"] == "GET"
    
    def test_detect_scanner_user_agent(self):
        line = '192.168.1.50 - - [15/Jan/2024:04:15:23 +0000] "GET /admin HTTP/1.1" 404 0 "-" "sqlmap/1.4"'
        entry = self.parser.parse_line(line)
        
        assert entry is not None
        assert entry.action == "scanner_request"
        assert entry.metadata["is_scanner"] is True
    
    def test_detect_path_traversal(self):
        line = '192.168.1.50 - - [15/Jan/2024:04:15:22 +0000] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" "Mozilla/5.0"'
        entry = self.parser.parse_line(line)
        
        assert entry is not None
        assert entry.action == "suspicious_request"
        assert entry.metadata["is_suspicious"] is True


class TestJSONLogParser:
    """Tests for JSONLogParser."""
    
    def setup_method(self):
        self.parser = JSONLogParser()
    
    def test_can_parse_json(self):
        line = '{"timestamp": "2024-01-15T03:30:00Z", "event": "login_attempt", "user": "admin"}'
        assert self.parser.can_parse(line) is True
    
    def test_can_parse_non_json(self):
        line = "Jan 15 03:22:15 server sshd[12345]: Failed password"
        assert self.parser.can_parse(line) is False
    
    def test_parse_json_event(self):
        line = '{"timestamp": "2024-01-15T03:30:00Z", "event": "login_attempt", "user": "admin", "ip": "192.168.1.200", "status": "failed"}'
        entry = self.parser.parse_line(line)
        
        assert entry is not None
        assert entry.user == "admin"
        assert entry.source_ip == "192.168.1.200"
        assert entry.action == "login_attempt"
        assert entry.log_type == LogType.JSON


class TestParserOrchestrator:
    """Tests for ParserOrchestrator."""
    
    def setup_method(self):
        self.orchestrator = ParserOrchestrator()
    
    def test_detect_auth_log_type(self):
        content = """Jan 15 03:22:15 server sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2
Jan 15 03:22:17 server sshd[12346]: Failed password for admin from 192.168.1.100 port 54322 ssh2"""
        
        log_type = self.orchestrator.detect_log_type(content)
        assert log_type == LogType.AUTH
    
    def test_detect_nginx_log_type(self):
        content = """192.168.1.50 - - [15/Jan/2024:04:15:22 +0000] "GET /admin HTTP/1.1" 404 0 "-" "Mozilla/5.0"
192.168.1.50 - - [15/Jan/2024:04:15:23 +0000] "GET /login HTTP/1.1" 200 1234 "-" "Mozilla/5.0" """
        
        log_type = self.orchestrator.detect_log_type(content)
        assert log_type == LogType.NGINX
    
    def test_parse_mixed_content(self):
        content = """Jan 15 03:22:15 server sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2
Jan 15 03:22:17 server sshd[12346]: Failed password for root from 192.168.1.100 port 54322 ssh2"""
        
        entries = self.orchestrator.parse(content)
        assert len(entries) == 2
        assert all(e.log_type == LogType.AUTH for e in entries)
