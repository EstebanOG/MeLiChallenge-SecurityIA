"""
Caso de uso para entrenamiento del modelo IoT.

Este caso de uso encapsula la lógica de negocio para entrenar el modelo
de detección de anomalías con datos IoT.
"""

from typing import List
from ...domain.entities.dto import TrainRequestDTO, TrainResponseDTO
from ...domain.entities.log_entry import LogEntry
from ..interfaces.anomaly_detector import AnomalyDetector


class TrainIoTModelUseCase:
    """Caso de uso para entrenamiento del modelo IoT."""
    
    def __init__(self, detector: AnomalyDetector):
        self.detector = detector
    
    def execute(self, request: TrainRequestDTO) -> TrainResponseDTO:
        """
        Ejecuta el entrenamiento del modelo con los datos proporcionados.
        
        Args:
            request: DTO con los logs para entrenamiento
            
        Returns:
            DTO con el resultado del entrenamiento
        """
        # Convertir DTOs a entidades del dominio
        logs = self._convert_to_log_entries(request.logs)
        
        # Entrenar modelo
        self.detector.fit(logs)
        
        return TrainResponseDTO(
            status="trained",
            samples=len(logs),
            file_path="models/isoforest.joblib",
            features=11  # Número de features del modelo IoT
        )
    
    def _convert_to_log_entries(self, log_items: List) -> List[LogEntry]:
        """Convierte DTOs a entidades LogEntry."""
        logs = []
        for item in log_items:
            log_entry = LogEntry(
                timestamp=item.timestamp,
                device_id=item.device_id,
                device_type=item.device_type,
                cpu_usage=item.cpu_usage,
                memory_usage=item.memory_usage,
                network_in_kb=item.network_in_kb,
                network_out_kb=item.network_out_kb,
                packet_rate=item.packet_rate,
                avg_response_time_ms=item.avg_response_time_ms,
                service_access_count=item.service_access_count,
                failed_auth_attempts=item.failed_auth_attempts,
                is_encrypted=item.is_encrypted,
                geo_location_variation=item.geo_location_variation,
                label=item.label,
            )
            logs.append(log_entry)
        return logs
