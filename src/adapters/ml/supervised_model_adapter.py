"""
Adaptador para el modelo supervisado de detección de amenazas.

Este adaptador implementa la interfaz SupervisedModelInterface
usando la implementación concreta del framework de ML.
"""

import os
import sys
from typing import Dict, Any, List
from ...application.interfaces.supervised_model_interface import SupervisedModelInterface

# Agregar path para importar el modelo
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from src.frameworks.ml.supervised_model import SupervisedThreatDetector


class SupervisedModelAdapter(SupervisedModelInterface):
    """Adaptador para el modelo supervisado de detección de amenazas."""
    
    def __init__(self, model_path: str = "models/supervised_model.joblib"):
        self.model_path = model_path
        self.detector = SupervisedThreatDetector(model_path)
        self._is_trained = False
    
    def train(self, dataset_path: str) -> Dict[str, Any]:
        """
        Entrena el modelo con el dataset especificado.
        
        Args:
            dataset_path: Ruta al archivo CSV del dataset
            
        Returns:
            Diccionario con métricas de entrenamiento
        """
        metrics = self.detector.train(dataset_path)
        self._is_trained = True
        return metrics
    
    def predict(self, log_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Predice si hay un ataque en los logs dados.
        
        Args:
            log_data: Lista de diccionarios con datos de logs
            
        Returns:
            Diccionario con predicción y confianza
        """
        return self.detector.predict(log_data)
    
    def is_trained(self) -> bool:
        """
        Verifica si el modelo está entrenado.
        
        Returns:
            True si el modelo está entrenado, False en caso contrario
        """
        # Primero verificar el estado interno
        if self._is_trained:
            return True
        
        # Si no está entrenado internamente, verificar si existe el archivo
        try:
            if not os.path.exists(self.model_path):
                return False
            
            # Intentar cargar el modelo para verificar que esté completo
            self.detector._load_model()
            self._is_trained = self.detector.is_trained
            return self._is_trained
        except Exception:
            return False
    
    def get_feature_importance(self) -> Dict[str, float]:
        """
        Retorna la importancia de las características.
        
        Returns:
            Diccionario con importancia de cada característica
        """
        return self.detector.get_feature_importance()
