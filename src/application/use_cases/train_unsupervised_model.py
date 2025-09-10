"""
Caso de uso para entrenar el modelo no supervisado de detección de anomalías.

Este caso de uso maneja el entrenamiento del modelo Isolation Forest
para detección de comportamientos anómalos.
"""

import os
from typing import Dict, Any
from ...domain.entities.dto import UnsupervisedTrainResponseDTO
from ..interfaces.anomaly_detector import AnomalyDetector


class TrainUnsupervisedModelUseCase:
    """Caso de uso para entrenar el modelo no supervisado."""
    
    def __init__(self, anomaly_detector: AnomalyDetector, model_path: str = "models/isoforest.joblib"):
        self.anomaly_detector = anomaly_detector
        self.model_path = model_path
    
    def execute(self) -> UnsupervisedTrainResponseDTO:
        """
        Ejecuta el entrenamiento del modelo no supervisado.
        
        Returns:
            UnsupervisedTrainResponseDTO con el resultado del entrenamiento
        """
        try:
            # Verificar si el dataset existe
            dataset_path = "notebooks/data/processed/dataset_complete.csv"
            if not os.path.exists(dataset_path):
                raise FileNotFoundError("Dataset no encontrado. Asegúrate de que el archivo esté en notebooks/data/processed/dataset_complete.csv")
            
            # Entrenar el modelo
            metrics = self.anomaly_detector.fit_from_dataset(dataset_path)
            
            # Preparar métricas para la respuesta (similar al supervisado)
            response_metrics = {
                "contamination": metrics.get('contamination', 0.2),
                "n_estimators": metrics.get('n_estimators', 200),
                "train_samples": metrics.get('train_samples', 0),
                "anomaly_threshold": metrics.get('threshold', 0.5),
                "model_ready": metrics.get('model_ready', False),
                "training_time": metrics.get('training_time', 0.0),
                "features_used": 9,  # Número de features utilizadas
                "algorithm": "Isolation Forest",
                "contamination_rate": f"{metrics.get('contamination', 0.2)*100:.1f}%",
                # Métricas de evaluación (si están disponibles)
                "auc_score": metrics.get('auc_score', 'N/A'),
                "precision": metrics.get('precision', 'N/A'),
                "recall": metrics.get('recall', 'N/A'),
                "f1_score": metrics.get('f1_score', 'N/A'),
                "accuracy": metrics.get('accuracy', 'N/A')
            }
            
            # Mensaje similar al supervisado
            base_message = f"Modelo no supervisado entrenado exitosamente. Muestras: {metrics.get('train_samples', 0)}, Contaminación: {metrics.get('contamination', 0.2):.2f}, Estimadores: {metrics.get('n_estimators', 200)}"
            
            # Agregar métricas de evaluación si están disponibles
            if metrics.get('auc_score') != 'N/A' and metrics.get('auc_score') is not None:
                eval_message = f" AUC: {metrics.get('auc_score', 0):.4f}, Precisión: {metrics.get('precision', 0):.4f}, Recall: {metrics.get('recall', 0):.4f}, F1: {metrics.get('f1_score', 0):.4f}"
                message = base_message + eval_message
            else:
                message = base_message
            
            return UnsupervisedTrainResponseDTO(
                success=True,
                message=message,
                model_path=self.model_path,
                training_time=metrics.get('training_time'),
                metrics=response_metrics
            )
            
        except FileNotFoundError:
            # Re-lanzar FileNotFoundError para que los tests puedan capturarla
            raise
        except Exception as e:
            # Lanzar la excepción original para que los tests puedan capturarla
            raise Exception(f"Error durante el entrenamiento: {str(e)}")
    
    def is_model_trained(self) -> bool:
        """
        Verifica si el modelo está entrenado.
        
        Returns:
            True si el modelo está entrenado, False en caso contrario
        """
        try:
            if not os.path.exists(self.model_path):
                return False
            
            return self.anomaly_detector.is_ready()
            
        except Exception:
            return False
    
    def get_model_status(self) -> Dict[str, Any]:
        """
        Obtiene el estado del modelo no supervisado.
        
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
                metrics_path = "models/isoforest_stats.json"
                if os.path.exists(metrics_path):
                    import json
                    with open(metrics_path, 'r') as f:
                        metrics = json.load(f)
                    # Formatear métricas similar al supervisado
                    status["metrics"] = {
                        "contamination": metrics.get('contamination', 'N/A'),
                        "n_estimators": metrics.get('n_estimators', 'N/A'),
                        "train_samples": metrics.get('train_samples', 'N/A'),
                        "anomaly_threshold": metrics.get('threshold', 'N/A'),
                        "algorithm": "Isolation Forest",
                        "features_used": 9,
                        "contamination_rate": f"{metrics.get('contamination', 0.2)*100:.1f}%" if isinstance(metrics.get('contamination'), (int, float)) else "N/A",
                        "training_time": metrics.get('training_time', 'N/A'),
                        # Métricas de evaluación
                        "auc_score": metrics.get('auc_score', 'N/A'),
                        "precision": metrics.get('precision', 'N/A'),
                        "recall": metrics.get('recall', 'N/A'),
                        "f1_score": metrics.get('f1_score', 'N/A'),
                        "accuracy": metrics.get('accuracy', 'N/A')
                    }
                else:
                    # Si no hay archivo de métricas, intentar cargar el modelo y obtener métricas básicas
                    if self.anomaly_detector.is_ready():
                        status["metrics"] = {
                            "contamination": "N/A - Métricas no guardadas",
                            "n_estimators": "N/A - Métricas no guardadas", 
                            "train_samples": "N/A - Métricas no guardadas",
                            "anomaly_threshold": "N/A - Métricas no guardadas",
                            "algorithm": "Isolation Forest",
                            "features_used": 9,
                            "note": "Modelo entrenado pero métricas no disponibles. Re-entrena para obtener métricas completas."
                        }
            except Exception as e:
                status["metrics"] = {
                    "error": f"No se pudieron cargar las métricas: {str(e)}"
                }
        else:
            status["metrics"] = {
                "contamination": "N/A - Modelo no entrenado",
                "n_estimators": "N/A - Modelo no entrenado",
                "train_samples": "N/A - Modelo no entrenado", 
                "anomaly_threshold": "N/A - Modelo no entrenado",
                "algorithm": "Isolation Forest",
                "features_used": 9
            }
        
        return status
