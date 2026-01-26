"""
Parser for JSON-formatted logs.
"""

import json
import re
from datetime import datetime
from typing import Optional, Any

from app.parsers.base import BaseParser
from app.models.log_entry import LogEntry, LogType


class JSONLogParser(BaseParser):
    """
    Parser for JSON-formatted application logs.
    
    Flexible parser that attempts to map common JSON log fields
    to the normalized LogEntry schema.
    
    Supports various timestamp formats and field naming conventions.
    """
    
    log_type = LogType.JSON
    
    # Common field name variations
    TIMESTAMP_FIELDS = ["timestamp", "time", "@timestamp", "datetime", "date", "ts", "created_at"]
    IP_FIELDS = ["ip", "source_ip", "client_ip", "remote_addr", "src_ip", "clientIP", "sourceIP"]
    USER_FIELDS = ["user", "username", "user_name", "userId", "user_id", "actor", "principal"]
    ACTION_FIELDS = ["action", "event", "event_type", "eventType", "type", "operation", "activity"]
    STATUS_FIELDS = ["status", "result", "outcome", "success", "level", "severity"]
    RESOURCE_FIELDS = ["resource", "target", "path", "url", "endpoint", "service"]
    MESSAGE_FIELDS = ["message", "msg", "description", "details", "text"]
    
    def can_parse(self, line: str) -> bool:
        """Check if line is valid JSON."""
        line = line.strip()
        if not line:
            return False
        
        # Quick check for JSON structure
        if not (line.startswith("{") and line.endswith("}")):
            return False
        
        try:
            json.loads(line)
            return True
        except json.JSONDecodeError:
            return False
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single JSON log line."""
        line = line.strip()
        if not line:
            return None
        
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        
        if not isinstance(data, dict):
            return None
        
        # Extract fields using flexible field mapping
        timestamp = self._extract_timestamp(data)
        source_ip = self._extract_field(data, self.IP_FIELDS)
        user = self._extract_field(data, self.USER_FIELDS)
        action = self._extract_field(data, self.ACTION_FIELDS) or "event"
        status = self._extract_field(data, self.STATUS_FIELDS)
        resource = self._extract_field(data, self.RESOURCE_FIELDS)
        message = self._extract_field(data, self.MESSAGE_FIELDS)
        
        # Normalize action to lowercase with underscores
        if action:
            action = self._normalize_action(action)
        
        # Build metadata with remaining fields
        metadata = {k: v for k, v in data.items() if v is not None}
        if message:
            metadata["message"] = message
        
        return LogEntry(
            timestamp=timestamp,
            source_ip=source_ip,
            user=user,
            action=action,
            resource=resource,
            status=status,
            raw_line=line,
            log_type=self.log_type,
            metadata=metadata,
        )
    
    def _extract_field(self, data: dict, field_names: list) -> Optional[str]:
        """Extract a field value trying multiple possible field names."""
        for field in field_names:
            # Try exact match
            if field in data and data[field] is not None:
                return str(data[field])
            
            # Try case-insensitive match
            for key in data.keys():
                if key.lower() == field.lower() and data[key] is not None:
                    return str(data[key])
        
        return None
    
    def _extract_timestamp(self, data: dict) -> datetime:
        """Extract and parse timestamp from various formats."""
        for field in self.TIMESTAMP_FIELDS:
            # Try exact match
            value = data.get(field)
            if value is None:
                # Try case-insensitive
                for key in data.keys():
                    if key.lower() == field.lower():
                        value = data[key]
                        break
            
            if value is not None:
                parsed = self._parse_timestamp(value)
                if parsed:
                    return parsed
        
        return datetime.now()
    
    def _parse_timestamp(self, value: Any) -> Optional[datetime]:
        """Parse timestamp from various formats."""
        if isinstance(value, datetime):
            return value
        
        if isinstance(value, (int, float)):
            # Unix timestamp (seconds or milliseconds)
            try:
                if value > 1e12:  # Milliseconds
                    return datetime.fromtimestamp(value / 1000)
                else:
                    return datetime.fromtimestamp(value)
            except (ValueError, OSError):
                return None
        
        if isinstance(value, str):
            # Try various date formats
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S",
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(value.replace("+00:00", "Z").rstrip("Z") + "Z" if "Z" not in value else value, fmt.rstrip("Z") + "Z" if "Z" in fmt else fmt)
                except ValueError:
                    continue
            
            # Try ISO format parsing
            try:
                # Remove timezone info for simpler parsing
                clean_value = re.sub(r'[+-]\d{2}:?\d{2}$', '', value)
                clean_value = clean_value.rstrip('Z')
                
                if '.' in clean_value:
                    return datetime.strptime(clean_value[:26], "%Y-%m-%dT%H:%M:%S.%f")
                else:
                    return datetime.strptime(clean_value[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                pass
        
        return None
    
    def _normalize_action(self, action: str) -> str:
        """Normalize action string to lowercase with underscores."""
        # Convert camelCase to snake_case
        action = re.sub(r'(?<!^)(?=[A-Z])', '_', action).lower()
        # Replace spaces and hyphens with underscores
        action = re.sub(r'[\s-]+', '_', action)
        # Remove consecutive underscores
        action = re.sub(r'_+', '_', action)
        return action.strip('_')
