"""
Normalized log entry model.
All parsers output to this common schema.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class LogType(str, Enum):
    """Supported log types."""
    AUTH = "auth"
    NGINX = "nginx"
    JSON = "json"
    UNKNOWN = "unknown"


class LogEntry(BaseModel):
    """
    Normalized log entry - common schema for all log types.
    
    This abstraction allows the detection engine to work uniformly
    regardless of the original log format.
    """
    
    timestamp: datetime = Field(
        description="When the event occurred"
    )
    source_ip: Optional[str] = Field(
        default=None,
        description="Source IP address if available"
    )
    user: Optional[str] = Field(
        default=None,
        description="Username involved in the event"
    )
    action: str = Field(
        description="Normalized action type (e.g., 'login_failed', 'request', 'error')"
    )
    resource: Optional[str] = Field(
        default=None,
        description="Target resource (e.g., URL path, service name)"
    )
    status: Optional[str] = Field(
        default=None,
        description="Status or result of the action"
    )
    raw_line: str = Field(
        description="Original log line for reference"
    )
    log_type: LogType = Field(
        default=LogType.UNKNOWN,
        description="Type of log this entry came from"
    )
    metadata: dict = Field(
        default_factory=dict,
        description="Additional parsed fields specific to log type"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "timestamp": "2024-01-15T03:22:15Z",
                "source_ip": "192.168.1.100",
                "user": "admin",
                "action": "login_failed",
                "resource": "sshd",
                "status": "failed",
                "raw_line": "Jan 15 03:22:15 server sshd[12345]: Failed password for admin from 192.168.1.100",
                "log_type": "auth",
                "metadata": {"port": 54321, "protocol": "ssh2"}
            }
        }
    )
