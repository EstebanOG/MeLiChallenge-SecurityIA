"""
Adaptador para el detector de amenazas supervisado.

Este adaptador implementa la interfaz ThreatDetectorInterface
usando la implementación concreta del modelo supervisado.
"""

import os
import sys
from typing import List, Dict, Any
from ...application.interfaces.threat_detector_interface import ThreatDetectorInterface

# Agregar path para importar el modelo
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from src.frameworks.ml.supervised_model import SupervisedThreatDetector


class SupervisedThreatDetectorAdapter(ThreatDetectorInterface):
    """Adaptador para el detector de amenazas supervisado."""
    
    def __init__(self, model_path: str = "models/supervised_model.joblib"):
        self.model_path = model_path
        self.detector = SupervisedThreatDetector(model_path)
        self._is_ready = False
        self._ensure_ready()
    
    def predict(self, log_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Predice si hay una amenaza en los logs dados.
        
        Args:
            log_data: Lista de diccionarios con datos de logs
            
        Returns:
            Diccionario con predicción y confianza
        """
        if not self._is_ready:
            return {
                'is_attack': False,
                'confidence': 0.0,
                'probability': 0.0,
                'reasoning': 'Detector no está listo para usar'
            }
        
        return self.detector.predict(log_data)
    
    def is_ready(self) -> bool:
        """
        Verifica si el detector está listo para usar.
        
        Returns:
            True si el detector está listo, False en caso contrario
        """
        return self._is_ready
    
    def _ensure_ready(self):
        """Asegura que el detector esté listo para usar."""
        try:
            if not os.path.exists(self.model_path):
                print("⚠️ [SUPERVISED] Modelo no encontrado.")
                return
            
            if not self.detector.is_trained:
                self.detector._load_model()
            
            self._is_ready = self.detector.is_trained
        except Exception as e:
            print(f"⚠️ [SUPERVISED] Error cargando modelo: {e}")
            self._is_ready = False
