"""
Configuración para modelos LLM.
"""

import os
from typing import Optional

def get_gemini_api_key() -> Optional[str]:
    """Obtiene la API key de Gemini desde variables de entorno."""
    return os.getenv('GEMINI_API_KEY')

def get_openai_api_key() -> Optional[str]:
    """Obtiene la API key de OpenAI desde variables de entorno."""
    return os.getenv('OPENAI_API_KEY')

def get_anthropic_api_key() -> Optional[str]:
    """Obtiene la API key de Anthropic desde variables de entorno."""
    return os.getenv('ANTHROPIC_API_KEY')

# Configuración por defecto
DEFAULT_LLM_CONFIG = {
    "gemini_model": "gemini-1.5-flash",
    "openai_model": "gpt-4o-mini",
    "anthropic_model": "claude-3-haiku-20240307",
    "max_tokens": 1000,
    "temperature": 0.1,  # Baja temperatura para análisis de seguridad
    "timeout": 30
}
