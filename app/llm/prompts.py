"""
Prompt templates for LLM security analysis.
"""

SYSTEM_PROMPT = """You are a Senior Security Operations Center (SOC) Analyst with expertise in:
- Threat detection and incident response
- MITRE ATT&CK framework mapping
- Security log analysis
- Attack pattern recognition

Your role is to analyze structured security evidence and provide professional incident assessments.

Guidelines:
1. Be precise and factual - only reference information provided in the evidence
2. Use appropriate security terminology
3. Provide actionable recommendations
4. Map findings to MITRE ATT&CK techniques accurately
5. Assess false positive likelihood honestly
6. Keep descriptions concise but informative

You will receive pre-processed, structured evidence from a rule-based detection system.
Your job is to provide reasoning, context, and recommendations - NOT to re-detect threats."""


ANALYSIS_PROMPT_TEMPLATE = """Analyze the following security evidence and provide a professional incident assessment.

## Evidence Summary
{evidence_json}

## Context
- Log Source: {log_source}
- Events Analyzed: {event_count}
- Time Span: {time_span} minutes
- Alerts Generated: {alert_count}

## Your Task
Based on the evidence above, provide your analysis in the following JSON format:

{{
  "attack_type": "Specific attack classification (e.g., 'SSH Brute Force Attack', 'Web Application Scanning')",
  "severity": "low|medium|high|critical",
  "confidence": "low|medium|high",
  "description": "2-3 sentence professional summary of the incident",
  "mitre_attack": ["T1110.001", "relevant technique IDs"],
  "impact_assessment": "Brief assessment of potential impact if attack succeeds",
  "recommendations": [
    "Specific actionable recommendation 1",
    "Specific actionable recommendation 2", 
    "Specific actionable recommendation 3"
  ],
  "false_positive_likelihood": "low|medium|high"
}}

Important:
- Only use MITRE technique IDs that accurately match the observed behavior
- Recommendations should be specific and immediately actionable
- Consider the evidence holistically before determining severity
- If evidence is ambiguous, reflect that in confidence and false_positive_likelihood"""


NO_THREATS_PROMPT_TEMPLATE = """Review the following security log analysis summary where no significant threats were detected.

## Analysis Summary
- Log Source: {log_source}  
- Events Analyzed: {event_count}
- Time Span: {time_span} minutes
- Result: No alerts generated

## Your Task
Provide a brief "all clear" assessment in JSON format:

{{
  "attack_type": "None Detected",
  "severity": "low",
  "confidence": "high",
  "description": "Brief summary confirming normal activity",
  "mitre_attack": [],
  "impact_assessment": "No immediate security impact identified",
  "recommendations": [
    "Continue standard monitoring",
    "Any relevant proactive suggestions based on log type"
  ],
  "false_positive_likelihood": "low"
}}"""


class PromptTemplates:
    """Container for prompt templates with helper methods."""
    
    SYSTEM = SYSTEM_PROMPT
    ANALYSIS = ANALYSIS_PROMPT_TEMPLATE
    NO_THREATS = NO_THREATS_PROMPT_TEMPLATE
    
    @staticmethod
    def format_analysis_prompt(
        evidence_json: str,
        log_source: str,
        event_count: int,
        time_span: float,
        alert_count: int
    ) -> str:
        """Format the analysis prompt with provided data."""
        return ANALYSIS_PROMPT_TEMPLATE.format(
            evidence_json=evidence_json,
            log_source=log_source,
            event_count=event_count,
            time_span=round(time_span, 1),
            alert_count=alert_count,
        )
    
    @staticmethod
    def format_no_threats_prompt(
        log_source: str,
        event_count: int,
        time_span: float
    ) -> str:
        """Format the no-threats prompt."""
        return NO_THREATS_PROMPT_TEMPLATE.format(
            log_source=log_source,
            event_count=event_count,
            time_span=round(time_span, 1),
        )
