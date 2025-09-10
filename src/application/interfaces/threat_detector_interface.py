"""
Interfaz para detectores de amenazas.

Esta interfaz define el contrato que debe implementar cualquier
detector de amenazas en el sistema.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any


class ThreatDetectorInterface(ABC):
    """Interfaz para detectores de amenazas."""
    
    @abstractmethod
    def predict(self, log_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Predice si hay una amenaza en los logs dados.
        
        Args:
            log_data: Lista de diccionarios con datos de logs
            
        Returns:
            Diccionario con predicción y confianza
        """
        pass
    
    @abstractmethod
    def is_ready(self) -> bool:
        """
        Verifica si el detector está listo para usar.
        
        Returns:
            True si el detector está listo, False en caso contrario
        """
        pass
