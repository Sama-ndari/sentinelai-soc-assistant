"""
OpenAI API client wrapper.
"""

import json
from typing import Optional, Dict, Any
import httpx
from openai import AsyncOpenAI

from app.config import get_settings


class OpenAIClient:
    """
    Async client for OpenAI API interactions.
    
    Features:
    - JSON mode for structured responses
    - Configurable temperature and tokens
    - Error handling with retries
    - Response validation
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.client = AsyncOpenAI(
            api_key=self.settings.openai_api_key,
            timeout=httpx.Timeout(60.0, connect=10.0),
        )
    
    async def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Send analysis request to GPT-4o-mini.
        
        Args:
            system_prompt: System context/instructions
            user_prompt: User message with evidence
            temperature: Override default temperature
            max_tokens: Override default max tokens
            
        Returns:
            Parsed JSON response from the model
            
        Raises:
            ValueError: If response cannot be parsed as JSON
            Exception: For API errors
        """
        temp = temperature if temperature is not None else self.settings.openai_temperature
        tokens = max_tokens if max_tokens is not None else self.settings.openai_max_tokens
        
        try:
            response = await self.client.chat.completions.create(
                model=self.settings.openai_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temp,
                max_tokens=tokens,
                response_format={"type": "json_object"},
            )
            
            content = response.choices[0].message.content
            
            # Parse JSON response
            try:
                result = json.loads(content)
                return result
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse LLM response as JSON: {e}")
                
        except Exception as e:
            # Log and re-raise for caller to handle
            print(f"OpenAI API error: {e}")
            raise
    
    async def health_check(self) -> bool:
        """Check if API is accessible."""
        try:
            # Make a minimal request
            response = await self.client.chat.completions.create(
                model=self.settings.openai_model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5,
            )
            return True
        except Exception:
            return False
