"""
Interfaz para servicios de dataset.

Define el contrato que deben cumplir todos los servicios
de gestión de datasets.
"""

from abc import ABC, abstractmethod
import pandas as pd


class DatasetServiceInterface(ABC):
    """Interfaz para servicios de dataset."""
    
    @abstractmethod
    def download_dataset(self, dataset_name: str) -> str:
        """
        Descarga el dataset desde la fuente externa.
        
        Args:
            dataset_name: Nombre del dataset
            
        Returns:
            Ruta al directorio del dataset descargado
        """
        pass
    
    @abstractmethod
    def load_dataset(self, data_dir: str) -> pd.DataFrame:
        """
        Carga el dataset desde el directorio especificado.
        
        Args:
            data_dir: Ruta al directorio del dataset
            
        Returns:
            DataFrame con los datos cargados
        """
        pass

    @abstractmethod
    def save_complete_dataset(self, df: pd.DataFrame) -> None:
        """
        Guarda el dataset completo sin procesar.
        
        Args:
            df: DataFrame completo a guardar
        """
        pass
