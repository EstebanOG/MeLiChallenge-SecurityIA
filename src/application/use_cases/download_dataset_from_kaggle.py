"""
Caso de uso para descargar dataset desde Kaggle.

Este caso de uso encapsula la lógica de negocio para descargar
y procesar datasets desde Kaggle.
"""

import time
from pathlib import Path
from ...domain.entities.dto import DatasetDownloadResponseDTO
from ...domain.entities.dataset_config import DEFAULT_DATASET
from ...domain.interfaces.dataset_service_interface import DatasetServiceInterface


class DownloadDatasetFromKaggleUseCase:
    """Caso de uso para descargar dataset desde Kaggle."""
    
    def __init__(self, dataset_service: DatasetServiceInterface):
        self.dataset_service = dataset_service
    
    def execute(self, dataset_name: str = DEFAULT_DATASET) -> DatasetDownloadResponseDTO:
        """
        Descarga el dataset desde Kaggle y lo guarda.
        
        Args:
            dataset_name: Nombre del dataset en Kaggle
            
        Returns:
            DTO con información de la descarga
            
        Raises:
            Exception: Si hay error en la descarga
        """
        start_time = time.time()
        
        try:
            # Descargar dataset
            download_path = self.dataset_service.download_dataset(dataset_name)
            
            # Cargar dataset para obtener información básica
            df = self.dataset_service.load_dataset(download_path)
            
            # Guardar dataset completo sin procesar
            self.dataset_service.save_complete_dataset(df)
            
            processing_time = time.time() - start_time
            
            return DatasetDownloadResponseDTO(
                success=True,
                message=f"Dataset '{dataset_name}' descargado y guardado exitosamente",
                dataset_name=dataset_name,
                download_path=str(download_path),
                total_rows=len(df),
                features=len(df.columns),
                processing_time=round(processing_time, 2)
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            raise Exception(f"Error descargando dataset '{dataset_name}': {str(e)}")
    
    def is_dataset_available(self) -> bool:
        """
        Verifica si el dataset ya está disponible localmente.
        
        Returns:
            True si el dataset está disponible, False en caso contrario
        """
        processed_dir = Path("data/processed")
        info_file = processed_dir / "dataset_info.json"
        return info_file.exists()
