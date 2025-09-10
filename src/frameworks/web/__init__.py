from .routes import create_app

# Re-exportar la función create_app desde routes.py
# para mantener compatibilidad con imports existentes
__all__ = ["create_app"]


