"""
Gateway para validación de disponibilidad de datasets.

Este gateway maneja la verificación de disponibilidad de datasets
en el sistema de archivos local, implementando la interfaz de dominio.
"""

from pathlib import Path
from ...domain.interfaces.dataset_validation_interface import DatasetValidationInterface


class FileSystemDatasetValidationGateway(DatasetValidationInterface):
    """
    Implementación del gateway de validación de datasets usando sistema de archivos.
    
    Esta implementación verifica la disponibilidad de datasets
    consultando el sistema de archivos local.
    """
    
    def __init__(self, processed_data_path: str = "data/processed"):
        """
        Inicializa el gateway con la ruta de datos procesados.
        
        Args:
            processed_data_path: Ruta al directorio de datos procesados
        """
        self.processed_data_path = Path(processed_data_path)
    
    def is_dataset_available(self) -> bool:
        """
        Verifica si el dataset está disponible localmente.
        
        Returns:
            True si el dataset está disponible, False en caso contrario
        """
        info_file = self.processed_data_path / "dataset_info.json"
        return info_file.exists()
    
    def get_dataset_availability_message(self) -> str:
        """
        Obtiene el mensaje de error estándar cuando el dataset no está disponible.
        
        Returns:
            Mensaje de error con instrucciones para descargar el dataset
        """
        return (
            "Dataset no encontrado. Por favor, descarga el dataset primero usando: "
            "POST /dataset/download"
        )
