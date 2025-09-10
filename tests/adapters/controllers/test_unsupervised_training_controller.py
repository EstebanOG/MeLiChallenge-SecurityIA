"""
Tests para el UnsupervisedTrainingController.

Prueba la funcionalidad del controlador que maneja los endpoints
de entrenamiento del modelo no supervisado.
"""

import pytest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from fastapi import FastAPI
from src.adapters.controllers.unsupervised_training_controller import UnsupervisedTrainingController
from src.application.use_cases.train_unsupervised_model import TrainUnsupervisedModelUseCase
from src.domain.entities.dto import UnsupervisedTrainResponseDTO


class TestUnsupervisedTrainingController:
    """Tests para el UnsupervisedTrainingController."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.mock_use_case = Mock(spec=TrainUnsupervisedModelUseCase)
        self.controller = UnsupervisedTrainingController(self.mock_use_case)
        self.app = FastAPI()
        self.app.include_router(self.controller.get_router())
        self.client = TestClient(self.app)
    
    def test_init(self):
        """Test de inicialización."""
        assert self.controller.train_unsupervised_use_case == self.mock_use_case
        assert self.controller.router is not None
    
    def test_train_unsupervised_model_success(self):
        """Test de entrenamiento exitoso del modelo no supervisado."""
        # Configurar mock
        mock_response = UnsupervisedTrainResponseDTO(
            success=True,
            message="Modelo no supervisado entrenado exitosamente. Muestras: 9520, Contaminación: 0.20, Estimadores: 200 AUC: 0.8500, Precisión: 0.7800, Recall: 0.8200, F1: 0.8000",
            model_path="models/isoforest.joblib",
            training_time=8.3,
            metrics={
                'contamination': 0.2,
                'n_estimators': 200,
                'train_samples': 9520,
                'anomaly_threshold': 0.5,
                'model_ready': True,
                'training_time': 8.3,
                'features_used': 9,
                'algorithm': 'Isolation Forest',
                'contamination_rate': '20.0%',
                'auc_score': 0.85,
                'precision': 0.78,
                'recall': 0.82,
                'f1_score': 0.80,
                'accuracy': 0.88
            }
        )
        self.mock_use_case.execute.return_value = mock_response
        
        # Ejecutar
        response = self.client.post("/train/unsupervised")
        
        # Verificar
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "Modelo no supervisado entrenado exitosamente" in data["message"]
        assert "Muestras: 9520" in data["message"]
        assert "Contaminación: 0.20" in data["message"]
        assert "Estimadores: 200" in data["message"]
        assert "AUC: 0.8500" in data["message"]
        assert "Precisión: 0.7800" in data["message"]
        assert "Recall: 0.8200" in data["message"]
        assert "F1: 0.8000" in data["message"]
        assert data["model_path"] == "models/isoforest.joblib"
        assert data["training_time"] == 8.3
        assert data["metrics"]["train_samples"] == 9520
        assert data["metrics"]["contamination"] == 0.2
        assert data["metrics"]["algorithm"] == "Isolation Forest"
        assert data["metrics"]["features_used"] == 9
        assert data["metrics"]["contamination_rate"] == "20.0%"
        
        # Verificar que se llamó al caso de uso
        self.mock_use_case.execute.assert_called_once()
    
    def test_train_unsupervised_model_dataset_not_found(self):
        """Test cuando el dataset no existe."""
        # Configurar mock
        self.mock_use_case.execute.side_effect = FileNotFoundError("Dataset no encontrado")
        
        # Ejecutar
        response = self.client.post("/train/unsupervised")
        
        # Verificar
        assert response.status_code == 404
        data = response.json()
        assert "Dataset no encontrado" in data["detail"]
    
    def test_train_unsupervised_model_training_error(self):
        """Test cuando ocurre un error durante el entrenamiento."""
        # Configurar mock
        self.mock_use_case.execute.side_effect = Exception("Error de entrenamiento")
        
        # Ejecutar
        response = self.client.post("/train/unsupervised")
        
        # Verificar
        assert response.status_code == 500
        data = response.json()
        assert "Error en entrenamiento no supervisado: Error de entrenamiento" in data["detail"]
    
    def test_get_unsupervised_model_status_success(self):
        """Test de obtención exitosa del estado del modelo."""
        # Configurar mock
        mock_status = {
            "is_trained": True,
            "model_path": "models/isoforest.joblib",
            "model_exists": True,
            "metrics": {
                "contamination": 0.2,
                "n_estimators": 200,
                "train_samples": 9520,
                "anomaly_threshold": 0.5
            }
        }
        self.mock_use_case.get_model_status.return_value = mock_status
        
        # Ejecutar
        response = self.client.get("/train/unsupervised/status")
        
        # Verificar
        assert response.status_code == 200
        data = response.json()
        assert data["is_trained"] is True
        assert data["model_path"] == "models/isoforest.joblib"
        assert data["model_exists"] is True
        assert data["metrics"]["train_samples"] == 9520
        assert data["metrics"]["algorithm"] == "Isolation Forest"
        assert data["metrics"]["features_used"] == 9
        assert data["metrics"]["contamination_rate"] == "20.0%"
        
        # Verificar que se llamó al caso de uso
        self.mock_use_case.get_model_status.assert_called_once()
    
    def test_get_unsupervised_model_status_error(self):
        """Test cuando ocurre un error al obtener el estado."""
        # Configurar mock
        self.mock_use_case.get_model_status.side_effect = Exception("Error obteniendo estado")
        
        # Ejecutar
        response = self.client.get("/train/unsupervised/status")
        
        # Verificar
        assert response.status_code == 500
        data = response.json()
        assert "Error obteniendo estado del modelo: Error obteniendo estado" in data["detail"]
    
    def test_get_router(self):
        """Test de obtención del router."""
        router = self.controller.get_router()
        assert router is not None
        assert len(router.routes) == 2  # POST /train/unsupervised y GET /train/unsupervised/status
