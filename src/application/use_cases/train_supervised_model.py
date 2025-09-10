"""
Caso de uso para entrenar el modelo supervisado de detección de amenazas.

Este caso de uso maneja el entrenamiento del modelo Gradient Boosting
para detección de ataques conocidos.
"""

import os
from typing import Dict, Any
from ...domain.entities.dto import SupervisedTrainResponseDTO
from ..interfaces.supervised_model_interface import SupervisedModelInterface


class TrainSupervisedModelUseCase:
    """Caso de uso para entrenar el modelo supervisado."""
    
    def __init__(self, supervised_model: SupervisedModelInterface, model_path: str = "models/supervised_model.joblib"):
        self.supervised_model = supervised_model
        self.model_path = model_path
    
    def execute(self) -> SupervisedTrainResponseDTO:
        """
        Ejecuta el entrenamiento del modelo supervisado.
        
        Returns:
            SupervisedTrainResponseDTO con el resultado del entrenamiento
        """
        try:
            # Verificar si el dataset existe
            dataset_path = "notebooks/data/processed/dataset_complete.csv"
            if not os.path.exists(dataset_path):
                return SupervisedTrainResponseDTO(
                    success=False,
                    message="Dataset no encontrado. Asegúrate de que el archivo esté en notebooks/data/processed/dataset_complete.csv",
                    model_path=None,
                    training_time=None,
                    metrics=None
                )
            
            # Entrenar el modelo
            metrics = self.supervised_model.train(dataset_path)
            
            # Preparar métricas para la respuesta
            response_metrics = {
                "auc_score": metrics['auc_score'],
                "precision": metrics['precision'],
                "recall": metrics['recall'],
                "f1_score": metrics['f1_score'],
                "train_samples": metrics['train_samples'],
                "test_samples": metrics['test_samples'],
                "feature_importance": self.supervised_model.get_feature_importance()
            }
            
            return SupervisedTrainResponseDTO(
                success=True,
                message=f"Modelo supervisado entrenado exitosamente. AUC: {metrics['auc_score']:.4f}, Precisión: {metrics['precision']:.4f}, Recall: {metrics['recall']:.4f}, F1: {metrics['f1_score']:.4f}",
                model_path=self.model_path,
                training_time=metrics.get('training_time'),
                metrics=response_metrics
            )
            
        except Exception as e:
            return SupervisedTrainResponseDTO(
                success=False,
                message=f"Error durante el entrenamiento: {str(e)}",
                model_path=None,
                training_time=None,
                metrics=None
            )
    
    def is_model_trained(self) -> bool:
        """
        Verifica si el modelo está entrenado.
        
        Returns:
            True si el modelo está entrenado, False en caso contrario
        """
        try:
            if not os.path.exists(self.model_path):
                return False
            
            return self.supervised_model.is_trained()
            
        except Exception:
            return False
    
    def get_model_status(self) -> Dict[str, Any]:
        """
        Obtiene el estado del modelo supervisado.
        
        Returns:
            Diccionario con información del estado del modelo
        """
        is_trained = self.is_model_trained()
        
        status = {
            "is_trained": is_trained,
            "model_path": self.model_path,
            "model_exists": os.path.exists(self.model_path) if self.model_path else False
        }
        
        if is_trained:
            try:
                # Cargar métricas si existen
                metrics_path = "models/supervised_model_metrics.json"
                if os.path.exists(metrics_path):
                    import json
                    with open(metrics_path, 'r') as f:
                        metrics = json.load(f)
                    status["metrics"] = metrics
                else:
                    # Si no hay archivo de métricas, intentar cargar el modelo y obtener métricas básicas
                    if self.supervised_model.is_trained():
                        status["metrics"] = {
                            "auc_score": "N/A - Métricas no guardadas",
                            "precision": "N/A - Métricas no guardadas", 
                            "recall": "N/A - Métricas no guardadas",
                            "f1_score": "N/A - Métricas no guardadas",
                            "note": "Modelo entrenado pero métricas no disponibles. Re-entrena para obtener métricas completas."
                        }
            except Exception as e:
                status["metrics"] = {
                    "error": f"No se pudieron cargar las métricas: {str(e)}"
                }
        else:
            status["metrics"] = {
                "auc_score": "N/A - Modelo no entrenado",
                "precision": "N/A - Modelo no entrenado",
                "recall": "N/A - Modelo no entrenado", 
                "f1_score": "N/A - Modelo no entrenado"
            }
        
        return status
