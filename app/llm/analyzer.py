"""
Security analyzer - orchestrates LLM analysis of security evidence.
"""

import json
from typing import Dict, Any, Optional

from app.llm.client import OpenAIClient
from app.llm.prompts import PromptTemplates
from app.models.incident import LLMAnalysis


class SecurityAnalyzer:
    """
    Orchestrates LLM-based security analysis.
    
    Takes structured evidence from the detection engine
    and uses GPT-4o-mini to provide reasoning and recommendations.
    """
    
    def __init__(self, client: Optional[OpenAIClient] = None):
        self.client = client or OpenAIClient()
    
    async def analyze(self, evidence: Dict[str, Any]) -> LLMAnalysis:
        """
        Analyze security evidence using LLM.
        
        Args:
            evidence: Structured evidence from EvidenceAggregator
            
        Returns:
            LLMAnalysis model with reasoning and recommendations
        """
        # Check if there are any alerts
        alert_count = evidence.get("analysis_summary", {}).get("alerts_generated", 0)
        
        if alert_count == 0:
            # Use no-threats prompt
            user_prompt = PromptTemplates.format_no_threats_prompt(
                log_source=evidence.get("analysis_summary", {}).get("log_source", "unknown"),
                event_count=evidence.get("analysis_summary", {}).get("total_events_analyzed", 0),
                time_span=evidence.get("timeline", {}).get("time_span_minutes", 0),
            )
        else:
            # Use full analysis prompt
            user_prompt = PromptTemplates.format_analysis_prompt(
                evidence_json=json.dumps(evidence, indent=2, default=str),
                log_source=evidence.get("analysis_summary", {}).get("log_source", "unknown"),
                event_count=evidence.get("analysis_summary", {}).get("total_events_analyzed", 0),
                time_span=evidence.get("timeline", {}).get("time_span_minutes", 0),
                alert_count=alert_count,
            )
        
        try:
            # Get LLM analysis
            response = await self.client.analyze(
                system_prompt=PromptTemplates.SYSTEM,
                user_prompt=user_prompt,
            )
            
            # Parse into LLMAnalysis model
            return LLMAnalysis(
                attack_type=response.get("attack_type", "Unknown"),
                severity=response.get("severity", "medium"),
                confidence=response.get("confidence", "medium"),
                description=response.get("description", "Analysis unavailable"),
                mitre_attack=response.get("mitre_attack", []),
                impact_assessment=response.get("impact_assessment", ""),
                recommendations=response.get("recommendations", []),
                false_positive_likelihood=response.get("false_positive_likelihood", "medium"),
            )
            
        except Exception as e:
            # Return fallback analysis on error
            return self._fallback_analysis(evidence, str(e))
    
    def _fallback_analysis(self, evidence: Dict[str, Any], error: str) -> LLMAnalysis:
        """
        Generate fallback analysis when LLM is unavailable.
        
        Uses rule-based evidence to create basic analysis.
        """
        alert_count = evidence.get("analysis_summary", {}).get("alerts_generated", 0)
        severity = evidence.get("analysis_summary", {}).get("overall_severity", "medium")
        
        if alert_count == 0:
            return LLMAnalysis(
                attack_type="None Detected",
                severity="low",
                confidence="medium",
                description="No significant security threats detected in analyzed logs. LLM analysis unavailable.",
                mitre_attack=[],
                impact_assessment="No immediate impact identified.",
                recommendations=["Continue standard monitoring procedures."],
                false_positive_likelihood="low",
            )
        
        # Extract attack types from indicators
        indicators = evidence.get("attack_indicators", [])
        attack_types = list(set(i.get("type", "unknown") for i in indicators))
        
        # Get MITRE techniques from evidence
        mitre = evidence.get("mitre_mapping", {}).get("techniques", [])
        
        return LLMAnalysis(
            attack_type=", ".join(attack_types) if attack_types else "Security Threat",
            severity=severity,
            confidence="medium",
            description=f"Detected {alert_count} security alert(s). LLM reasoning unavailable ({error}). Review evidence manually.",
            mitre_attack=mitre,
            impact_assessment="Manual review recommended due to LLM unavailability.",
            recommendations=[
                "Review detected alerts manually",
                "Check source IPs against threat intelligence",
                "Monitor affected accounts for suspicious activity",
            ],
            false_positive_likelihood="medium",
        )
