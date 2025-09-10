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

@router.get("/", response_model=InfoResponseDTO)
def get_info():
    """Obtiene información sobre el proyecto y el modelo."""
    return InfoResponseDTO(
        project="Threat Intelligence & Anomaly Detection API",
        version="2.1.0",
        description="API para detección de anomalías y análisis de threat intelligence en logs de seguridad",
        features=[
            "Detección de anomalías en tiempo real",
            "Pipeline de agentes inteligentes (Supervised, Unsupervised, Decision, Report)",
            "Modelado de amenazas con frameworks STRIDE y MITRE ATT&CK",
            "Detección de intrusiones en sesiones de red",
            "Análisis de comportamiento de autenticación",
            "Indicadores de Compromiso (IoC) automatizados",
            "Entrenamiento de modelos supervisados y no supervisados",
            "Integración con datasets de Kaggle",
            "Arquitectura Clean Architecture",
            "Documentación interactiva con Swagger UI",
            "Pruebas automatizadas (Unit, Integration, E2E)",
            "Integración con Snyk para seguridad de dependencias"
        ]
    )
