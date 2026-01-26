"""
FastAPI API routes.
"""

import time
from typing import Optional, List
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.models.log_entry import LogType
from app.models.incident import IncidentReport
from app.database.repositories import IncidentRepository
from app.api.dependencies import (
    get_parser,
    get_detection_engine,
    get_aggregator,
    get_analyzer,
    get_report_generator,
)


router = APIRouter()
templates = Jinja2Templates(directory="templates")


# Request/Response Models
class AnalyzeRequest(BaseModel):
    """Request model for log analysis."""
    log_content: str
    log_type: Optional[str] = "auto"


class AnalyzeResponse(BaseModel):
    """Response model for log analysis."""
    incident: IncidentReport
    processing_time_ms: int


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str


# Routes
@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the main dashboard."""
    incidents = await IncidentRepository.get_all(limit=10)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "incidents": incidents}
    )


@router.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(status="healthy", version="1.0.0")


@router.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_logs(request: AnalyzeRequest):
    """
    Analyze log content for security threats.
    
    This is the main endpoint that:
    1. Parses logs into normalized format
    2. Runs detection rules
    3. Aggregates evidence
    4. Gets LLM analysis
    5. Generates incident report
    """
    start_time = time.time()
    
    # Validate input
    if not request.log_content or not request.log_content.strip():
        raise HTTPException(status_code=400, detail="Log content is required")
    
    # Determine log type
    log_type = None
    if request.log_type and request.log_type != "auto":
        try:
            log_type = LogType(request.log_type)
        except ValueError:
            pass  # Will auto-detect
    
    # Get dependencies
    parser = get_parser()
    engine = get_detection_engine()
    aggregator = get_aggregator()
    analyzer = get_analyzer()
    report_gen = get_report_generator()
    
    # 1. Parse logs
    entries = parser.parse(request.log_content, log_type)
    
    if not entries:
        raise HTTPException(
            status_code=400, 
            detail="Could not parse any log entries. Check log format."
        )
    
    # Detect log type from parsed entries
    detected_type = entries[0].log_type.value if entries else "unknown"
    
    # 2. Run detection
    alerts = engine.analyze(entries)
    
    # 3. Aggregate evidence
    evidence = aggregator.aggregate(alerts, entries, detected_type)
    
    # 4. LLM analysis
    llm_analysis = await analyzer.analyze(evidence)
    
    # Calculate duration
    duration_ms = int((time.time() - start_time) * 1000)
    
    # 5. Generate report
    incident = report_gen.generate(
        alerts=alerts,
        llm_analysis=llm_analysis,
        evidence=evidence,
        log_source=detected_type,
        events_analyzed=len(entries),
        analysis_duration_ms=duration_ms,
    )
    
    # 6. Save to database
    await IncidentRepository.save(incident)
    
    return AnalyzeResponse(
        incident=incident,
        processing_time_ms=duration_ms,
    )


@router.post("/api/analyze/upload")
async def analyze_upload(
    file: UploadFile = File(...),
    log_type: str = Form("auto"),
):
    """
    Analyze uploaded log file.
    
    Accepts file upload and processes it through the analysis pipeline.
    """
    # Read file content
    content = await file.read()
    
    try:
        log_content = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="File must be UTF-8 encoded text"
        )
    
    # Use the main analyze endpoint
    request = AnalyzeRequest(log_content=log_content, log_type=log_type)
    return await analyze_logs(request)


@router.get("/api/incidents", response_model=List[IncidentReport])
async def list_incidents(
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
):
    """
    List incidents with optional filtering.
    
    Args:
        limit: Maximum number of incidents to return
        offset: Pagination offset
        severity: Filter by severity level
    """
    if severity:
        incidents = await IncidentRepository.get_by_severity(severity)
    else:
        incidents = await IncidentRepository.get_all(limit=limit, offset=offset)
    
    return incidents


@router.get("/api/incidents/{incident_id}", response_model=IncidentReport)
async def get_incident(incident_id: str):
    """Get a specific incident by ID."""
    incident = await IncidentRepository.get_by_id(incident_id)
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return incident


@router.patch("/api/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, status: str):
    """Update incident status."""
    valid_statuses = {"open", "investigating", "resolved", "closed"}
    
    if status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {valid_statuses}"
        )
    
    success = await IncidentRepository.update_status(incident_id, status)
    
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return {"message": "Status updated", "new_status": status}


@router.get("/api/rules")
async def list_rules():
    """List all active detection rules."""
    engine = get_detection_engine()
    return engine.get_rule_info()
