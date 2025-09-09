"""
Controlador para endpoints de salud y información del sistema.

Este controlador maneja los endpoints relacionados con el estado del sistema
y información general del proyecto.
"""

from fastapi import APIRouter
from ...domain.entities.dto import HealthResponseDTO, InfoResponseDTO

router = APIRouter()


@router.get("/health", response_model=HealthResponseDTO)
def health():
    """Endpoint de salud del sistema."""
    return HealthResponseDTO(
        status="ok", 
        dataset="Anomaly Detection and Threat Intelligence"
    )

#TODO: Add features
@router.get("/", response_model=InfoResponseDTO)
def get_info():
    """Obtiene información sobre el proyecto y el modelo."""
    return InfoResponseDTO(
        project="Threat Intelligence & Anomaly Detection API",
        version="2.1.0",
        description="API para detección de anomalías y análisis de threat intelligence en logs de seguridad",
        features=[
            "Detección de anomalías en tiempo real"
        ]
    )
