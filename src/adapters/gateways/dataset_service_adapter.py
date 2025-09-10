"""
Adaptador para servicios de dataset.

Este adaptador implementa la interfaz de dominio usando
el servicio de framework externo.
"""

from typing import Dict, Any
import pandas as pd
from ...domain.interfaces.dataset_service_interface import DatasetServiceInterface
from ...frameworks.external.dataset_service import DatasetService


class DatasetServiceAdapter(DatasetServiceInterface):
    """Adaptador para servicios de dataset."""
    
    def __init__(self, dataset_service: DatasetService = None):
        self.dataset_service = dataset_service or DatasetService()
    
    def download_dataset(self, dataset_name: str) -> str:
        """Descarga el dataset desde la fuente externa."""
        return self.dataset_service.download_dataset(dataset_name)
    
    def load_dataset(self, data_dir: str) -> pd.DataFrame:
        """Carga el dataset desde el directorio especificado."""
        return self.dataset_service.load_dataset(data_dir)
    
    def save_complete_dataset(self, df: pd.DataFrame) -> None:
        """Guarda el dataset completo sin procesar."""
        self.dataset_service.save_complete_dataset(df)
    
    def get_dataset_sample(self, size: int = 10) -> Dict[str, Any]:
        """Obtiene una muestra del dataset procesado."""
        return self.dataset_service.get_dataset_sample(size)