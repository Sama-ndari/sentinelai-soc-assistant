"""
FastAPI dependencies for dependency injection.
"""

from functools import lru_cache

from app.parsers.base import ParserOrchestrator
from app.detection.engine import DetectionEngine
from app.detection.aggregator import EvidenceAggregator
from app.llm.analyzer import SecurityAnalyzer
from app.reports.generator import ReportGenerator


@lru_cache()
def get_parser() -> ParserOrchestrator:
    """Get cached parser orchestrator instance."""
    return ParserOrchestrator()


@lru_cache()
def get_detection_engine() -> DetectionEngine:
    """Get cached detection engine instance."""
    return DetectionEngine()


@lru_cache()
def get_aggregator() -> EvidenceAggregator:
    """Get cached evidence aggregator instance."""
    return EvidenceAggregator()


def get_analyzer() -> SecurityAnalyzer:
    """Get security analyzer instance (new each request for async safety)."""
    return SecurityAnalyzer()


@lru_cache()
def get_report_generator() -> ReportGenerator:
    """Get cached report generator instance."""
    return ReportGenerator()
