"""
Application configuration using Pydantic Settings.
Loads from environment variables and .env file.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )
    
    # OpenAI Configuration
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_temperature: float = 0.2
    openai_max_tokens: int = 1000
    
    # Application Settings
    app_env: str = "development"
    debug: bool = True
    app_name: str = "SOC Assistant"
    
    # Database
    database_url: str = "sqlite:///./data/soc_assistant.db"
    
    # Detection Thresholds
    brute_force_threshold: int = 5
    brute_force_window_minutes: int = 5
    frequency_threshold_per_minute: int = 100


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
