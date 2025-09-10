"""
Interfaz para el modelo supervisado de detección de amenazas.

Esta interfaz define el contrato que debe implementar cualquier
modelo supervisado de detección de amenazas.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class SupervisedModelInterface(ABC):
    """Interfaz para modelos supervisados de detección de amenazas."""
    
    @abstractmethod
    def train(self, dataset_path: str) -> Dict[str, Any]:
        """
        Entrena el modelo con el dataset especificado.
        
        Args:
            dataset_path: Ruta al archivo CSV del dataset
            
        Returns:
            Diccionario con métricas de entrenamiento
        """
        pass
    
    @abstractmethod
    def predict(self, log_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Predice si hay un ataque en los logs dados.
        
        Args:
            log_data: Lista de diccionarios con datos de logs
            
        Returns:
            Diccionario con predicción y confianza
        """
        pass
    
    @abstractmethod
    def is_trained(self) -> bool:
        """
        Verifica si el modelo está entrenado.
        
        Returns:
            True si el modelo está entrenado, False en caso contrario
        """
        pass
    
    @abstractmethod
    def get_feature_importance(self) -> Dict[str, float]:
        """
        Retorna la importancia de las características.
        
        Returns:
            Diccionario con importancia de cada característica
        """
        pass
