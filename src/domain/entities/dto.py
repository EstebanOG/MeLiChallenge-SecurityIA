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

class IoTLogItemDTO(BaseModel):
    """DTO para un item de log de IoT."""
    timestamp: str
    device_id: str
    device_type: str
    cpu_usage: float = Field(ge=0, le=100)
    memory_usage: float = Field(ge=0, le=100)
    network_in_kb: int = Field(ge=0)
    network_out_kb: int = Field(ge=0)
    packet_rate: int = Field(ge=0)
    avg_response_time_ms: float = Field(ge=0)
    service_access_count: int = Field(ge=0)
    failed_auth_attempts: int = Field(ge=0)
    is_encrypted: int = Field(ge=0, le=1)
    geo_location_variation: float = Field(ge=0)
    label: Optional[str] = None


class IoTAnalyzeRequestDTO(BaseModel):
    """DTO para solicitud de análisis de logs IoT."""
    logs: List[IoTLogItemDTO]


class TrainRequestDTO(BaseModel):
    """DTO para solicitud de entrenamiento."""
    logs: List[IoTLogItemDTO]


# ============================================================================
# DTOs DE SALIDA (Responses)
# ============================================================================

class IoTAnalyzeResponseDTO(BaseModel):
    """DTO para respuesta de análisis de logs IoT."""
    trace_id: str
    score: float
    decision: Dict[str, Any]
    batch_size: int


class TrainResponseDTO(BaseModel):
    """DTO para respuesta de entrenamiento."""
    status: str
    samples: int
    file_path: str
    features: int


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
    supported_device_types: List[str]


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
