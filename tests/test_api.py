"""
Tests for API endpoints.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


class TestHealthEndpoint:
    """Tests for health check endpoint."""
    
    def test_health_check(self, client):
        """Health endpoint should return healthy status."""
        response = client.get("/api/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data


class TestRulesEndpoint:
    """Tests for rules listing endpoint."""
    
    def test_list_rules(self, client):
        """Should return list of active detection rules."""
        response = client.get("/api/rules")
        
        assert response.status_code == 200
        rules = response.json()
        
        assert isinstance(rules, list)
        assert len(rules) > 0
        
        # Check rule structure
        for rule in rules:
            assert "rule_id" in rule
            assert "rule_name" in rule
            assert "description" in rule
            assert "mitre_tactics" in rule
            assert "mitre_techniques" in rule


class TestAnalyzeEndpoint:
    """Tests for log analysis endpoint."""
    
    def test_analyze_empty_content(self, client):
        """Should reject empty log content."""
        response = client.post(
            "/api/analyze",
            json={"log_content": "", "log_type": "auto"}
        )
        
        assert response.status_code == 400
    
    def test_analyze_unparseable_content(self, client):
        """Should reject content that can't be parsed."""
        response = client.post(
            "/api/analyze",
            json={"log_content": "random gibberish that's not a log", "log_type": "auto"}
        )
        
        assert response.status_code == 400
    
    def test_analyze_valid_auth_logs(self, client):
        """Should successfully analyze valid auth logs."""
        log_content = """Jan 15 03:22:15 server sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2
Jan 15 03:22:17 server sshd[12346]: Failed password for admin from 192.168.1.100 port 54322 ssh2
Jan 15 03:22:19 server sshd[12347]: Failed password for root from 192.168.1.100 port 54323 ssh2
Jan 15 03:22:21 server sshd[12348]: Failed password for admin from 192.168.1.100 port 54324 ssh2
Jan 15 03:22:23 server sshd[12349]: Failed password for ubuntu from 192.168.1.100 port 54325 ssh2
Jan 15 03:22:25 server sshd[12350]: Failed password for admin from 192.168.1.100 port 54326 ssh2"""
        
        response = client.post(
            "/api/analyze",
            json={"log_content": log_content, "log_type": "auth"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "incident" in data
        assert "processing_time_ms" in data
        
        incident = data["incident"]
        assert "id" in incident
        assert "title" in incident
        assert "severity" in incident
        assert "recommendations" in incident


class TestIncidentsEndpoint:
    """Tests for incidents listing endpoint."""
    
    def test_list_incidents(self, client):
        """Should return list of incidents."""
        response = client.get("/api/incidents")
        
        assert response.status_code == 200
        incidents = response.json()
        
        assert isinstance(incidents, list)
    
    def test_list_incidents_with_pagination(self, client):
        """Should support pagination parameters."""
        response = client.get("/api/incidents?limit=5&offset=0")
        
        assert response.status_code == 200
    
    def test_get_nonexistent_incident(self, client):
        """Should return 404 for nonexistent incident."""
        response = client.get("/api/incidents/INC-NOTREAL123")
        
        assert response.status_code == 404
