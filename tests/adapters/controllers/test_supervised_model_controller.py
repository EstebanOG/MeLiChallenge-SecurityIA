"""
Tests para el SupervisedModelController.

Prueba la funcionalidad del controlador que maneja los endpoints
de entrenamiento y estado del modelo supervisado.
"""

import pytest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from fastapi import FastAPI
from src.adapters.controllers.supervised_model_controller import SupervisedModelController
from src.application.use_cases.train_supervised_model import TrainSupervisedModelUseCase
from src.domain.entities.dto import SupervisedTrainResponseDTO


class TestSupervisedModelController:
    """Tests para el SupervisedModelController."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        # Mock del caso de uso
        self.mock_use_case = Mock(spec=TrainSupervisedModelUseCase)
        self.controller = SupervisedModelController(self.mock_use_case)
        
        # Crear app FastAPI para testing
        self.app = FastAPI()
        self.app.include_router(self.controller.get_router())
        self.client = TestClient(self.app)
    
    def test_init_with_use_case(self):
        """Test de inicialización con caso de uso."""
        assert self.controller.train_use_case == self.mock_use_case
    
    def test_get_router_returns_router(self):
        """Test que get_router retorna un router válido."""
        router = self.controller.get_router()
        assert router is not None
        assert hasattr(router, 'routes')
        assert len(router.routes) > 0
    
    def test_train_supervised_model_success(self):
        """Test de entrenamiento exitoso del modelo supervisado."""
        # Configurar mock
        mock_response = SupervisedTrainResponseDTO(
            success=True,
            message="Modelo supervisado entrenado exitosamente. AUC: 0.8789, Precisión: 0.8234, Recall: 0.8012, F1: 0.8121",
            model_path="models/supervised_model.joblib",
            training_time=None,
            metrics={
                "auc_score": 0.8789,
                "precision": 0.8234,
                "recall": 0.8012,
                "f1_score": 0.8121,
                "train_samples": 7629,
                "test_samples": 1908,
                "feature_importance": {
                    "failed_logins": 0.25,
                    "ip_reputation_score": 0.20,
                    "login_attempts": 0.15
                }
            }
        )
        self.mock_use_case.execute.return_value = mock_response
        
        # Ejecutar request
        response = self.client.post("/train/supervised")
        
        # Verificar
        assert response.status_code == 200
        data = response.json()
        assert data["success"] == True
        assert "Modelo supervisado entrenado exitosamente" in data["message"]
        assert data["model_path"] == "models/supervised_model.joblib"
        assert data["metrics"]["auc_score"] == 0.8789
        assert data["metrics"]["precision"] == 0.8234
        assert data["metrics"]["recall"] == 0.8012
        assert data["metrics"]["f1_score"] == 0.8121
        assert data["metrics"]["train_samples"] == 7629
        assert data["metrics"]["test_samples"] == 1908
        assert "failed_logins" in data["metrics"]["feature_importance"]
        
        # Verificar que se llamó el caso de uso
        self.mock_use_case.execute.assert_called_once()
    
    def test_train_supervised_model_error(self):
        """Test de error en entrenamiento del modelo supervisado."""
        # Configurar mock para lanzar error
        self.mock_use_case.execute.side_effect = Exception("Error en entrenamiento del modelo")
        
        # Ejecutar request
        response = self.client.post("/train/supervised")
        
        # Verificar
        assert response.status_code == 500
        data = response.json()
        assert data["detail"] == "Error en entrenamiento del modelo supervisado: Error en entrenamiento del modelo"
    
    def test_train_supervised_model_dataset_not_found(self):
        """Test de error cuando no se encuentra el dataset."""
        # Configurar mock para lanzar error específico
        self.mock_use_case.execute.side_effect = FileNotFoundError("Dataset no encontrado")
        
        # Ejecutar request
        response = self.client.post("/train/supervised")
        
        # Verificar
        assert response.status_code == 500
        data = response.json()
        assert "Error en entrenamiento del modelo supervisado: Dataset no encontrado" in data["detail"]
    
    def test_get_supervised_model_status_success(self):
        """Test de obtención exitosa del estado del modelo."""
        # Configurar mock
        mock_status = {
            "is_trained": True,
            "model_path": "models/supervised_model.joblib",
            "model_exists": True,
            "metrics": {
                "auc_score": 0.8789,
                "precision": 0.8234,
                "recall": 0.8012,
                "f1_score": 0.8121,
                "train_samples": 7629,
                "test_samples": 1908,
                "feature_importance": {
                    "failed_logins": 0.25,
                    "ip_reputation_score": 0.20
                }
            }
        }
        self.mock_use_case.get_model_status.return_value = mock_status
        
        # Ejecutar request
        response = self.client.get("/model/supervised/status")
        
        # Verificar
        assert response.status_code == 200
        data = response.json()
        assert data["is_trained"] == True
        assert data["model_path"] == "models/supervised_model.joblib"
        assert data["model_exists"] == True
        assert data["metrics"]["auc_score"] == 0.8789
        assert data["metrics"]["precision"] == 0.8234
        
        # Verificar que se llamó el método
        self.mock_use_case.get_model_status.assert_called_once()
    
    def test_get_supervised_model_status_not_trained(self):
        """Test de estado cuando el modelo no está entrenado."""
        # Configurar mock
        mock_status = {
            "is_trained": False,
            "model_path": "models/supervised_model.joblib",
            "model_exists": False,
            "metrics": {
                "auc_score": "N/A - Modelo no entrenado",
                "precision": "N/A - Modelo no entrenado",
                "recall": "N/A - Modelo no entrenado",
                "f1_score": "N/A - Modelo no entrenado"
            }
        }
        self.mock_use_case.get_model_status.return_value = mock_status
        
        # Ejecutar request
        response = self.client.get("/model/supervised/status")
        
        # Verificar
        assert response.status_code == 200
        data = response.json()
        assert data["is_trained"] == False
        assert data["model_exists"] == False
        assert data["metrics"]["auc_score"] == "N/A - Modelo no entrenado"
        assert data["metrics"]["precision"] == "N/A - Modelo no entrenado"
    
    def test_get_supervised_model_status_error(self):
        """Test de error al obtener el estado del modelo."""
        # Configurar mock para lanzar error
        self.mock_use_case.get_model_status.side_effect = Exception("Error al obtener estado")
        
        # Ejecutar request
        response = self.client.get("/model/supervised/status")
        
        # Verificar
        assert response.status_code == 500
        data = response.json()
        assert data["detail"] == "Error obteniendo estado del modelo: Error al obtener estado"
    
    def test_train_endpoint_http_methods(self):
        """Test que el endpoint de entrenamiento solo acepta POST."""
        # GET no debe estar permitido
        response = self.client.get("/train/supervised")
        assert response.status_code == 405  # Method Not Allowed
        
        # PUT no debe estar permitido
        response = self.client.put("/train/supervised")
        assert response.status_code == 405
        
        # DELETE no debe estar permitido
        response = self.client.delete("/train/supervised")
        assert response.status_code == 405
    
    def test_status_endpoint_http_methods(self):
        """Test que el endpoint de estado solo acepta GET."""
        # POST no debe estar permitido
        response = self.client.post("/model/supervised/status")
        assert response.status_code == 405  # Method Not Allowed
        
        # PUT no debe estar permitido
        response = self.client.put("/model/supervised/status")
        assert response.status_code == 405
        
        # DELETE no debe estar permitido
        response = self.client.delete("/model/supervised/status")
        assert response.status_code == 405
    
    def test_train_response_dto_validation(self):
        """Test de validación del DTO de respuesta de entrenamiento."""
        # Configurar mock con datos válidos
        mock_response = SupervisedTrainResponseDTO(
            success=True,
            message="Test message",
            model_path="test/path.joblib",
            training_time=120.5,
            metrics={
                "auc_score": 0.85,
                "precision": 0.80,
                "recall": 0.75,
                "f1_score": 0.77,
                "train_samples": 1000,
                "test_samples": 200,
                "feature_importance": {"test": 0.5}
            }
        )
        self.mock_use_case.execute.return_value = mock_response
        
        # Ejecutar request
        response = self.client.post("/train/supervised")
        
        # Verificar que la respuesta es válida
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert "message" in data
        assert "model_path" in data
        assert "metrics" in data
    
    def test_status_response_validation(self):
        """Test de validación de la respuesta de estado."""
        # Configurar mock
        mock_status = {
            "is_trained": True,
            "model_path": "test/path.joblib",
            "model_exists": True,
            "metrics": {
                "auc_score": 0.85,
                "precision": 0.80,
                "recall": 0.75,
                "f1_score": 0.77
            }
        }
        self.mock_use_case.get_model_status.return_value = mock_status
        
        # Ejecutar request
        response = self.client.get("/model/supervised/status")
        
        # Verificar que la respuesta contiene los campos esperados
        assert response.status_code == 200
        data = response.json()
        assert "is_trained" in data
        assert "model_path" in data
        assert "model_exists" in data
        assert "metrics" in data
