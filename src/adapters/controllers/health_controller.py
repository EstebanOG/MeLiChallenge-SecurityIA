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
        dataset="IoT Anomaly Detection"
    )


@router.get("/", response_model=InfoResponseDTO)
def get_info():
    """Obtiene información sobre el proyecto y el modelo."""
    return InfoResponseDTO(
        project="IoT Anomaly Detection API",
        version="2.0.0",
        description="API para detección de anomalías en dispositivos IoT",
        features=[
            "Detección de anomalías en tiempo real",
            "Análisis de métricas de dispositivos IoT",
            "Modelo Isolation Forest adaptado",
            "Pipeline de agentes LangGraph"
        ],
        supported_device_types=[
            "thermostat", "smart", "sensor", "camera", 
            "lock", "hub", "appliance", "wearable"
        ]
    )
