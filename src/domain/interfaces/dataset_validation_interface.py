"""
Interfaz para validación de disponibilidad de datasets.

Esta interfaz define el contrato para verificar la disponibilidad
de datasets en el sistema, siguiendo el principio de inversión de dependencias.
"""

from typing import Protocol


class DatasetValidationInterface(Protocol):
    """
    Interfaz para validación de disponibilidad de datasets.
    
    Esta interfaz permite verificar si un dataset está disponible
    y obtener mensajes de error apropiados cuando no lo está.
    """
    
    def is_dataset_available(self) -> bool:
        """
        Verifica si el dataset está disponible.
        
        Returns:
            True si el dataset está disponible, False en caso contrario
        """
        ...
    
    def get_dataset_availability_message(self) -> str:
        """
        Obtiene el mensaje de error estándar cuando el dataset no está disponible.
        
        Returns:
            Mensaje de error con instrucciones para descargar el dataset
        """
        ...
