"""
Configuración de API Keys para el sistema de detección de amenazas.

PLANTILLA PARA DESARROLLADORES:
1. Copia este archivo como 'api_config.py'
2. Reemplaza 'tu_gemini_api_key_aqui' con tu API key real de Gemini
3. NO commitees el archivo 'api_config.py' al repositorio
"""

import os

# Configuración de API Keys
GEMINI_API_KEY = "tu_gemini_api_key_aqui"  # Reemplazar con tu API key real

# Otras configuraciones
DEBUG = True
LOG_LEVEL = "INFO"
GEMINI_MODEL = "gemini-1.5-flash"
MAX_TOKENS = 1000
TEMPERATURE = 0.1

# Función para obtener la API key
def get_gemini_api_key():
    """Obtiene la API key de Gemini desde variables de entorno o configuración local."""
    # Primero intentar desde variables de entorno
    env_key = os.getenv('GEMINI_API_KEY')
    if env_key:
        return env_key
    
    # Si no está en variables de entorno, usar la configuración local
    return GEMINI_API_KEY

# Función para verificar configuración
def check_config():
    """Verifica que la configuración esté correcta."""
    api_key = get_gemini_api_key()
    
    if api_key == "tu_gemini_api_key_aqui":
        print("⚠️ API Key no configurada. Reemplaza 'tu_gemini_api_key_aqui' con tu API key real.")
        return False
    
    print(f"✅ API Key configurada: ***{api_key[-4:]}")
    return True

if __name__ == "__main__":
    check_config()
