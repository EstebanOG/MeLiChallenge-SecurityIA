"""
Gateway para acceso a datasets.

Implementa servicios de acceso a datos externos.
"""

from typing import List, Dict, Any
from ...frameworks.external.iot_dataset_service import IoTDatasetService
from ...frameworks.external.kaggle_service import download_and_extract_dataset


class DatasetGateway:
    """Gateway para acceso a datasets externos."""
    
    def __init__(self):
        self.iot_service = IoTDatasetService()
    
    def download_dataset(self, dataset_name: str) -> str:
        """Descarga un dataset desde Kaggle."""
        return download_and_extract_dataset(dataset_name)
    
    def load_dataset(self, dataset_path: str) -> List[Dict[str, Any]]:
        """Carga un dataset desde un archivo."""
        return self.iot_service.load_dataset(dataset_path)
    
    def get_dataset_info(self) -> Dict[str, Any]:
        """Obtiene información del dataset."""
        return self.iot_service.get_dataset_info()
