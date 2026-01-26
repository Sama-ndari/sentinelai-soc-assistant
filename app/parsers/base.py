"""
Abstract base class for log parsers.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from app.models.log_entry import LogEntry, LogType


class BaseParser(ABC):
    """
    Abstract base class for all log parsers.
    
    Each parser must implement:
    - can_parse(): Check if a line matches this parser's format
    - parse_line(): Parse a single log line into LogEntry
    """
    
    log_type: LogType = LogType.UNKNOWN
    
    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """
        Check if this parser can handle the given log line.
        
        Args:
            line: A single log line
            
        Returns:
            True if this parser can parse the line
        """
        pass
    
    @abstractmethod
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single log line into a normalized LogEntry.
        
        Args:
            line: A single log line
            
        Returns:
            LogEntry if successful, None if parsing fails
        """
        pass
    
    def parse_content(self, content: str) -> List[LogEntry]:
        """
        Parse multiple log lines from content string.
        
        Args:
            content: Multi-line string of log entries
            
        Returns:
            List of successfully parsed LogEntry objects
        """
        entries = []
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            entry = self.parse_line(line)
            if entry:
                entries.append(entry)
        
        return entries


class ParserOrchestrator:
    """
    Orchestrates multiple parsers to handle mixed or unknown log formats.
    """
    
    def __init__(self):
        # Import here to avoid circular imports
        from app.parsers.auth_parser import AuthLogParser
        from app.parsers.nginx_parser import NginxLogParser
        from app.parsers.json_parser import JSONLogParser
        
        self.parsers: List[BaseParser] = [
            AuthLogParser(),
            NginxLogParser(),
            JSONLogParser(),
        ]
    
    def detect_log_type(self, content: str) -> LogType:
        """
        Detect the log type from content sample.
        
        Args:
            content: Log content to analyze
            
        Returns:
            Detected LogType
        """
        lines = content.strip().split("\n")[:10]  # Sample first 10 lines
        
        type_counts = {LogType.AUTH: 0, LogType.NGINX: 0, LogType.JSON: 0}
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            for parser in self.parsers:
                if parser.can_parse(line):
                    type_counts[parser.log_type] += 1
                    break
        
        # Return the type with the most matches
        if max(type_counts.values()) == 0:
            return LogType.UNKNOWN
        
        return max(type_counts, key=type_counts.get)
    
    def parse(self, content: str, log_type: Optional[LogType] = None) -> List[LogEntry]:
        """
        Parse log content, auto-detecting type if not specified.
        
        Args:
            content: Log content to parse
            log_type: Optional log type hint
            
        Returns:
            List of parsed LogEntry objects
        """
        if log_type and log_type != LogType.UNKNOWN:
            # Use specified parser
            for parser in self.parsers:
                if parser.log_type == log_type:
                    return parser.parse_content(content)
        
        # Auto-detect and parse
        detected_type = self.detect_log_type(content)
        
        if detected_type == LogType.UNKNOWN:
            # Try each parser and use the one that works best
            best_result = []
            for parser in self.parsers:
                result = parser.parse_content(content)
                if len(result) > len(best_result):
                    best_result = result
            return best_result
        
        for parser in self.parsers:
            if parser.log_type == detected_type:
                return parser.parse_content(content)
        
        return []
