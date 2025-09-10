"""
DTOs (Data Transfer Objects) para la comunicación entre capas.

Estos objetos representan los datos que se transfieren entre la capa de presentación
y la capa de aplicación, manteniendo la separación de responsabilidades.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from dataclasses import dataclass


# ============================================================================
# DTOs DE ENTRADA (Requests)
# ============================================================================

class ThreatLogItemDTO(BaseModel):
    """DTO para un item de log de threat intelligence."""
    session_id: str
    network_packet_size: int = Field(ge=0)
    protocol_type: str
    login_attempts: int = Field(ge=0)
    session_duration: float = Field(ge=0)
    encryption_used: str
    ip_reputation_score: float = Field(ge=0, le=1)
    failed_logins: int = Field(ge=0)
    browser_type: str
    unusual_time_access: int = Field(ge=0, le=1)
    attack_detected: Optional[int] = Field(ge=0, le=1, default=None)


class ThreatAnalyzeRequestDTO(BaseModel):
    """DTO para solicitud de análisis de logs de threat intelligence."""
    logs: List[ThreatLogItemDTO]


class TrainRequestDTO(BaseModel):
    """DTO para solicitud de entrenamiento."""
    logs: List[ThreatLogItemDTO]


# ============================================================================
# DTOs DE SALIDA (Responses)
# ============================================================================

class ThreatAnalyzeResponseDTO(BaseModel):
    """DTO para respuesta de análisis de logs de threat intelligence."""
    trace_id: str
    score: float
    decision: Dict[str, Any]
    batch_size: int
    threat_modeling: Optional[Dict[str, Any]] = None


class TrainResponseDTO(BaseModel):
    """DTO para respuesta de entrenamiento."""
    status: str
    samples: int
    file_path: str
    features: int


class SupervisedTrainResponseDTO(BaseModel):
    """DTO para respuesta de entrenamiento del modelo supervisado."""
    success: bool
    message: str
    model_path: Optional[str] = None
    training_time: Optional[float] = None
    metrics: Optional[Dict[str, Any]] = None


class UnsupervisedTrainResponseDTO(BaseModel):
    """DTO para respuesta de entrenamiento del modelo no supervisado."""
    success: bool
    message: str
    model_path: Optional[str] = None
    training_time: Optional[float] = None
    metrics: Optional[Dict[str, Any]] = None


class DatasetInfoDTO(BaseModel):
    """DTO para información del dataset."""
    total_rows: int
    labeled_rows: int
    unlabeled_rows: int
    columns: List[str]
    label_distribution: Dict[str, int]
    device_type_distribution: Dict[str, int]
    anomaly_ratio: float


class DatasetSampleDTO(BaseModel):
    """DTO para muestra del dataset."""
    sample_size: int
    total_rows: int
    data: List[Dict[str, Any]]


class HealthResponseDTO(BaseModel):
    """DTO para respuesta de salud del sistema."""
    status: str
    dataset: str


class InfoResponseDTO(BaseModel):
    """DTO para información del proyecto."""
    project: str
    version: str
    description: str
    features: List[str]


# ============================================================================
# DTOs DE ERROR
# ============================================================================

@dataclass
class ErrorResponseDTO:
    """DTO para respuestas de error."""
    error_code: str
    message: str
    details: Optional[Dict[str, Any]] = None
    trace_id: Optional[str] = None

