"""
Caso de uso para entrenamiento del modelo IoT desde Kaggle.

Este caso de uso encapsula la lógica de negocio para descargar datos de Kaggle
y entrenar el modelo de detección de anomalías.
"""

from typing import List
import pandas as pd
from pathlib import Path

from ...domain.entities.dto import TrainResponseDTO
from ...domain.entities.log_entry import LogEntry
from ..interfaces.anomaly_detector import AnomalyDetector
from ...frameworks.external.iot_dataset_service import IoTDatasetService


class TrainIoTModelFromKaggleUseCase:
    """Caso de uso para entrenamiento del modelo IoT desde Kaggle."""
    
    def __init__(self, detector: AnomalyDetector, dataset_service: IoTDatasetService):
        self.detector = detector
        self.dataset_service = dataset_service
    
    def execute(self) -> TrainResponseDTO:
        """
        Ejecuta el entrenamiento del modelo descargando datos de Kaggle.
        
        Returns:
            DTO con el resultado del entrenamiento
        """
        # Descargar dataset
        print("📥 Descargando dataset de IoT desde Kaggle...")
        dataset_path = self.dataset_service.download_dataset()
        
        # Cargar datos
        print("📊 Cargando dataset...")
        df = self.dataset_service.load_dataset(dataset_path)
        
        # Split del dataset
        print("✂️ Dividiendo dataset...")
        labeled_df, unlabeled_df = self.dataset_service.split_dataset(df, labeled_ratio=0.2)
        
        # Guardar datasets procesados
        print("💾 Guardando datasets procesados...")
        self.dataset_service.save_datasets(labeled_df, unlabeled_df)
        
        # Convertir a LogEntry para entrenamiento
        print("🤖 Entrenando modelo...")
        logs = self._convert_dataframe_to_log_entries(labeled_df)
        
        # Entrenar modelo
        self.detector.fit(logs)
        
        return TrainResponseDTO(
            status="trained_from_kaggle",
            samples=len(logs),
            file_path="models/isoforest.joblib",
            features=11
        )
    
    def _convert_dataframe_to_log_entries(self, df: pd.DataFrame) -> List[LogEntry]:
        """Convierte DataFrame a entidades LogEntry."""
        logs = []
        
        if not df.empty:
            for _, row in df.iterrows():
                log_entry = LogEntry(
                    timestamp=str(row['timestamp']),
                    device_id=str(row['device_id']),
                    device_type=str(row['device_type']),
                    cpu_usage=float(row['cpu_usage']),
                    memory_usage=float(row['memory_usage']),
                    network_in_kb=int(row['network_in_kb']),
                    network_out_kb=int(row['network_out_kb']),
                    packet_rate=int(row['packet_rate']),
                    avg_response_time_ms=float(row['avg_response_time_ms']),
                    service_access_count=int(row['service_access_count']),
                    failed_auth_attempts=int(row['failed_auth_attempts']),
                    is_encrypted=int(row['is_encrypted']),
                    geo_location_variation=float(row['geo_location_variation']),
                    label=str(row['label']) if pd.notna(row['label']) else None,
                )
                logs.append(log_entry)
        
        return logs
