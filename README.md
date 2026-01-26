# SOC Assistant - AI-Powered Security Log Analyzer

An intelligent Security Operations Center (SOC) assistant that combines **rule-based threat detection** with **LLM-powered analysis** to analyze security logs and generate professional incident reports.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green.svg)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o--mini-purple.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Overview

SOC Assistant demonstrates a **production-ready architecture** for AI-augmented security operations:

- **Hybrid Detection**: Deterministic rule-based detection for reliability, LLM reasoning for context
- **Privacy-First**: Raw logs never sent to LLM—only structured evidence summaries
- **MITRE ATT&CK Mapping**: Industry-standard threat classification
- **Real-Time Analysis**: Sub-second rule execution with async LLM processing

### Why This Architecture?

Real SOC tools don't blindly feed logs to AI. This project implements the pattern used by enterprise security platforms:

1. **Deterministic Detection** catches known patterns reliably
2. **Evidence Aggregation** structures findings for analysis
3. **LLM Reasoning** provides context, impact assessment, and recommendations
4. **Human-Readable Reports** match real SOC ticket formats

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SOC Assistant                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │  Log Input   │───▶│   Parsers    │───▶│  Normalized  │       │
│  │ (File/Paste) │    │ Auth/Nginx/  │    │  Log Entries │       │
│  └──────────────┘    │    JSON      │    └──────┬───────┘       │
│                      └──────────────┘           │               │
│                                                 ▼               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Detection Engine                        │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐  │   │
│  │  │Brute Force │  │Suspicious  │  │Frequency Anomaly   │  │   │
│  │  │   Rule     │  │  IP Rule   │  │      Rule          │  │   │
│  │  └────────────┘  └────────────┘  └────────────────────┘  │   │
│  └──────────────────────────┬───────────────────────────────┘   │
│                             │                                   │
│                             ▼                                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Alerts     │───▶│  Evidence    │───▶│  GPT-4o-mini │       │
│  │  Generated   │    │ Aggregator   │    │   Analysis   │       │
│  └──────────────┘    └──────────────┘    └──────┬───────┘       │
│                                                 │               │
│                                                 ▼               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   SQLite     │◀───│   Report     │◀───│  Incident    │       │
│  │   Storage    │    │  Generator   │    │   Report     │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Features

### Detection Rules

| Rule | Description | MITRE ATT&CK |
|------|-------------|--------------|
| **Brute Force Detection** | Failed login attempts from single IP | T1110.001 |
| **Suspicious IP Behavior** | Multi-user targeting, scanner detection | T1595, T1190 |
| **Frequency Anomaly** | Request rate spikes, off-hours activity | T1498 |

### Supported Log Formats

- **Auth Logs**: Linux auth.log, sshd, sudo events
- **Nginx Logs**: Combined access log format
- **JSON Logs**: Flexible schema with auto-field detection

### Incident Reports Include

- Attack type classification
- Severity assessment (low/medium/high/critical)
- MITRE ATT&CK technique mapping
- Evidence summary
- Actionable recommendations
- False positive likelihood assessment

## Quick Start

### Prerequisites

- Python 3.11+
- OpenAI API key

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/soc-assistant.git
cd soc-assistant

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Run the Application

```bash
# Start the server
uvicorn app.main:app --reload

# Open browser to http://localhost:8000
```

### Quick Test

```bash
# Analyze sample brute force attack
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d @data/samples/auth_brute_force.log
```

## Usage

### Web Dashboard

1. Navigate to `http://localhost:8000`
2. Select log type or use auto-detect
3. Upload a log file or paste log content
4. Click "Analyze Logs"
5. View the generated incident report

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Analyze log content |
| `POST` | `/api/analyze/upload` | Upload and analyze log file |
| `GET` | `/api/incidents` | List all incidents |
| `GET` | `/api/incidents/{id}` | Get incident details |
| `PATCH` | `/api/incidents/{id}/status` | Update incident status |
| `GET` | `/api/rules` | List active detection rules |
| `GET` | `/api/health` | Health check |

### Example API Request

```python
import requests

response = requests.post(
    "http://localhost:8000/api/analyze",
    json={
        "log_content": """Jan 15 03:22:15 server sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2
Jan 15 03:22:17 server sshd[12346]: Failed password for admin from 192.168.1.100 port 54322 ssh2
...""",
        "log_type": "auth"
    }
)

incident = response.json()["incident"]
print(f"Severity: {incident['severity']}")
print(f"Attack Type: {incident['attack_type']}")
print(f"Recommendations: {incident['recommendations']}")
```

## Project Structure

```
soc-assistant/
├── app/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration management
│   ├── models/              # Pydantic data models
│   │   ├── log_entry.py     # Normalized log schema
│   │   ├── alert.py         # Detection alert model
│   │   └── incident.py      # Incident report model
│   ├── parsers/             # Log format parsers
│   │   ├── auth_parser.py   # Linux auth log parser
│   │   ├── nginx_parser.py  # Nginx access log parser
│   │   └── json_parser.py   # Generic JSON parser
│   ├── detection/           # Detection engine
│   │   ├── engine.py        # Rule orchestrator
│   │   ├── aggregator.py    # Evidence aggregation
│   │   └── rules/           # Detection rules
│   │       ├── brute_force.py
│   │       ├── suspicious_ip.py
│   │       └── frequency.py
│   ├── llm/                 # LLM integration
│   │   ├── client.py        # OpenAI API wrapper
│   │   ├── prompts.py       # Prompt templates
│   │   └── analyzer.py      # Analysis orchestration
│   ├── reports/             # Report generation
│   │   └── generator.py     # Incident report builder
│   ├── database/            # Data persistence
│   │   ├── db.py            # SQLite setup
│   │   └── repositories.py  # Data access layer
│   └── api/                 # API layer
│       ├── routes.py        # FastAPI endpoints
│       └── dependencies.py  # Dependency injection
├── templates/
│   └── index.html           # Web dashboard
├── data/
│   └── samples/             # Sample attack logs
├── requirements.txt
└── README.md
```

## Key Design Decisions

### 1. Hybrid Detection Architecture

**Why**: Pure ML/LLM detection is unreliable for security. Rule-based detection provides deterministic, auditable results. LLM adds reasoning and context.

**How**: Detection rules run first, generating structured alerts. Only aggregated evidence (not raw logs) goes to the LLM for analysis.

### 2. Evidence Abstraction

**Why**: Sending raw logs to LLMs is expensive, slow, and risks data leakage. Structured evidence enables focused analysis.

**How**: The `EvidenceAggregator` transforms alerts into a summary format containing only metrics and indicators.

### 3. MITRE ATT&CK Integration

**Why**: Industry-standard framework that recruiters and security teams recognize. Demonstrates real-world knowledge.

**How**: Each detection rule maps to specific tactics and techniques. LLM validates and may add additional mappings.

### 4. SQLite for Storage

**Why**: Zero configuration, portable, perfect for demos. Real deployments would use PostgreSQL or similar.

**How**: Async SQLite via `aiosqlite` for non-blocking database operations.

## Extending the System

### Adding a New Detection Rule

```python
# app/detection/rules/my_rule.py
from app.detection.rules.base import DetectionRule
from app.models.alert import Alert, Severity

class MyCustomRule(DetectionRule):
    rule_id = "CUSTOM_001"
    rule_name = "My Custom Detection"
    description = "Detects custom attack pattern"
    mitre_tactics = ["TA0001"]
    mitre_techniques = ["T1190"]
    
    def evaluate(self, entries):
        alerts = []
        # Your detection logic here
        return alerts
```

### Adding a New Log Parser

```python
# app/parsers/my_parser.py
from app.parsers.base import BaseParser

class MyLogParser(BaseParser):
    log_type = LogType.CUSTOM
    
    def can_parse(self, line: str) -> bool:
        # Return True if this parser handles this format
        pass
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        # Parse line into LogEntry
        pass
```

## Sample Output

### Incident Report (JSON)

```json
{
  "id": "INC-A1B2C3D4",
  "title": "[HIGH] SSH Brute Force Attack",
  "attack_type": "Credential Brute Force",
  "severity": "high",
  "description": "A sustained brute force attack was detected targeting SSH authentication. 31 failed login attempts were observed from IP 192.168.1.100 over 5 minutes, targeting multiple user accounts including admin, root, and ubuntu.",
  "mitre_attack": ["T1110.001", "T1110.003"],
  "recommendations": [
    "Block source IP 192.168.1.100 at the firewall immediately",
    "Enable account lockout policies after 5 failed attempts",
    "Implement fail2ban or similar automated blocking",
    "Review targeted accounts for signs of compromise",
    "Consider implementing SSH key-based authentication"
  ],
  "evidence_summary": {
    "total_alerts": 1,
    "source_ips": ["192.168.1.100"],
    "affected_users": ["admin", "root", "ubuntu", "test"],
    "time_range": {
      "duration_minutes": 5.5
    }
  }
}
```

## Tech Stack

- **Backend**: Python 3.11, FastAPI, Pydantic
- **Database**: SQLite with aiosqlite
- **LLM**: OpenAI GPT-4o-mini
- **Frontend**: HTML, Tailwind CSS (CDN)
- **Architecture**: Async/await, dependency injection

## License

MIT License - feel free to use this project as a portfolio piece or starting point for your own security tools.

## Author

Built as a portfolio project demonstrating practical AI integration in security operations.

---

**Note**: This is a demonstration project. For production use, consider:
- Additional log format support
- More sophisticated detection rules
- Integration with threat intelligence feeds
- Role-based access control
- Audit logging
- Horizontal scaling architecture
