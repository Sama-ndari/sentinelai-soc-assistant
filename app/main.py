"""
FastAPI application entry point.
SOC Assistant - AI-Powered Security Log Analysis
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.database.db import init_database
from app.api.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown events."""
    # Startup: Initialize database
    await init_database()
    yield
    # Shutdown: Cleanup if needed


settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="AI-Powered Security Operations Center Assistant. "
                "Analyzes security logs using hybrid detection (rule-based + LLM reasoning).",
    version="1.0.0",
    lifespan=lifespan,
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include API routes
app.include_router(router)

# Templates for rendering HTML
templates = Jinja2Templates(directory="templates")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
    )
