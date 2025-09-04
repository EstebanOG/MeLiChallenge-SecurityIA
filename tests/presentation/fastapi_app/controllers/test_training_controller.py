"""
Tests para el controlador de entrenamiento.

Estos tests verifican los endpoints de entrenamiento del modelo IoT.
"""

import pytest
from unittest.mock import Mock
from fastapi.testclient import TestClient
from src.presentation.fastapi_app.controllers.training_controller import TrainingController
from src.application.use_cases.train_iot_model import TrainIoTModelUseCase
from src.application.use_cases.train_iot_model_from_kaggle import TrainIoTModelFromKaggleUseCase
from src.domain.entities.dto import TrainRequestDTO, TrainResponseDTO, IoTLogItemDTO


class TestTrainingController:
    """Tests para TrainingController."""
    
    def setup_method(self):
        """Setup para cada test."""
        self.mock_train_use_case = Mock(spec=TrainIoTModelUseCase)
        self.mock_train_from_kaggle_use_case = Mock(spec=TrainIoTModelFromKaggleUseCase)
        self.controller = TrainingController(
            self.mock_train_use_case,
            self.mock_train_from_kaggle_use_case
        )
        self.client = TestClient(self.controller.get_router())
    
    def test_train_iot_model_success(self):
        """Test entrenamiento exitoso con datos proporcionados."""
        # Arrange
        request_data = {
            "logs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "device_id": "device_001",
                    "device_type": "thermostat",
                    "cpu_usage": 50.0,
                    "memory_usage": 60.0,
                    "network_in_kb": 1000,
                    "network_out_kb": 500,
                    "packet_rate": 100,
                    "avg_response_time_ms": 50.0,
                    "service_access_count": 10,
                    "failed_auth_attempts": 0,
                    "is_encrypted": 1,
                    "geo_location_variation": 0.1,
                    "label": "normal"
                }
            ]
        }
        
        expected_response = TrainResponseDTO(
            status="trained",
            samples=1,
            file_path="models/isoforest.joblib",
            features=11
        )
        
        self.mock_train_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.post("/train/iot", json=request_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "trained"
        assert data["samples"] == 1
        assert data["file_path"] == "models/isoforest.joblib"
        assert data["features"] == 11
        
        # Verificar que se llamó al caso de uso
        self.mock_train_use_case.execute.assert_called_once()
        call_args = self.mock_train_use_case.execute.call_args[0][0]
        assert isinstance(call_args, TrainRequestDTO)
        assert len(call_args.logs) == 1
        assert call_args.logs[0].device_id == "device_001"
    
    def test_train_iot_model_multiple_logs(self):
        """Test entrenamiento con múltiples logs."""
        # Arrange
        request_data = {
            "logs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "device_id": "device_001",
                    "device_type": "thermostat",
                    "cpu_usage": 50.0,
                    "memory_usage": 60.0,
                    "network_in_kb": 1000,
                    "network_out_kb": 500,
                    "packet_rate": 100,
                    "avg_response_time_ms": 50.0,
                    "service_access_count": 10,
                    "failed_auth_attempts": 0,
                    "is_encrypted": 1,
                    "geo_location_variation": 0.1,
                    "label": "normal"
                },
                {
                    "timestamp": "2024-01-01T01:00:00Z",
                    "device_id": "device_002",
                    "device_type": "sensor",
                    "cpu_usage": 75.0,
                    "memory_usage": 80.0,
                    "network_in_kb": 2000,
                    "network_out_kb": 1000,
                    "packet_rate": 200,
                    "avg_response_time_ms": 100.0,
                    "service_access_count": 20,
                    "failed_auth_attempts": 1,
                    "is_encrypted": 0,
                    "geo_location_variation": 0.2,
                    "label": "anomaly"
                }
            ]
        }
        
        expected_response = TrainResponseDTO(
            status="trained",
            samples=2,
            file_path="models/isoforest.joblib",
            features=11
        )
        
        self.mock_train_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.post("/train/iot", json=request_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "trained"
        assert data["samples"] == 2
        assert data["file_path"] == "models/isoforest.joblib"
        assert data["features"] == 11
        
        # Verificar que se llamó al caso de uso con 2 logs
        self.mock_train_use_case.execute.assert_called_once()
        call_args = self.mock_train_use_case.execute.call_args[0][0]
        assert len(call_args.logs) == 2
        assert call_args.logs[0].device_id == "device_001"
        assert call_args.logs[1].device_id == "device_002"
    
    def test_train_iot_model_empty_logs(self):
        """Test entrenamiento con lista vacía de logs."""
        # Arrange
        request_data = {"logs": []}
        
        expected_response = TrainResponseDTO(
            status="trained",
            samples=0,
            file_path="models/isoforest.joblib",
            features=11
        )
        
        self.mock_train_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.post("/train/iot", json=request_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "trained"
        assert data["samples"] == 0
        assert data["file_path"] == "models/isoforest.joblib"
        assert data["features"] == 11
    
    def test_train_iot_model_validation_error(self):
        """Test entrenamiento con datos de validación inválidos."""
        # Arrange
        request_data = {
            "logs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "device_id": "device_001",
                    "device_type": "thermostat",
                    "cpu_usage": -1.0,  # Inválido: debe ser >= 0
                    "memory_usage": 60.0,
                    "network_in_kb": 1000,
                    "network_out_kb": 500,
                    "packet_rate": 100,
                    "avg_response_time_ms": 50.0,
                    "service_access_count": 10,
                    "failed_auth_attempts": 0,
                    "is_encrypted": 1,
                    "geo_location_variation": 0.1,
                    "label": "normal"
                }
            ]
        }
        
        # Act
        response = self.client.post("/train/iot", json=request_data)
        
        # Assert
        assert response.status_code == 422  # Validation Error
        data = response.json()
        assert "detail" in data
    
    def test_train_iot_model_use_case_exception(self):
        """Test entrenamiento cuando el caso de uso lanza una excepción."""
        # Arrange
        request_data = {
            "logs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "device_id": "device_001",
                    "device_type": "thermostat",
                    "cpu_usage": 50.0,
                    "memory_usage": 60.0,
                    "network_in_kb": 1000,
                    "network_out_kb": 500,
                    "packet_rate": 100,
                    "avg_response_time_ms": 50.0,
                    "service_access_count": 10,
                    "failed_auth_attempts": 0,
                    "is_encrypted": 1,
                    "geo_location_variation": 0.1,
                    "label": "normal"
                }
            ]
        }
        
        self.mock_train_use_case.execute.side_effect = Exception("Error en entrenamiento")
        
        # Act
        response = self.client.post("/train/iot", json=request_data)
        
        # Assert
        assert response.status_code == 500
        data = response.json()
        assert "Error en entrenamiento" in data["detail"]
    
    def test_train_iot_model_from_kaggle_success(self):
        """Test entrenamiento exitoso desde Kaggle."""
        # Arrange
        expected_response = TrainResponseDTO(
            status="trained_from_kaggle",
            samples=1000,
            file_path="models/isoforest.joblib",
            features=11
        )
        
        self.mock_train_from_kaggle_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.post("/train/iot/kaggle")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "trained_from_kaggle"
        assert data["samples"] == 1000
        assert data["file_path"] == "models/isoforest.joblib"
        assert data["features"] == 11
        
        # Verificar que se llamó al caso de uso
        self.mock_train_from_kaggle_use_case.execute.assert_called_once()
    
    def test_train_iot_model_from_kaggle_exception(self):
        """Test entrenamiento desde Kaggle cuando lanza una excepción."""
        # Arrange
        self.mock_train_from_kaggle_use_case.execute.side_effect = Exception("Error en entrenamiento desde Kaggle")
        
        # Act
        response = self.client.post("/train/iot/kaggle")
        
        # Assert
        assert response.status_code == 500
        data = response.json()
        assert "Error en entrenamiento desde Kaggle" in data["detail"]
    
    def test_train_iot_model_wrong_method(self):
        """Test que el endpoint de entrenamiento solo acepta POST."""
        # Act & Assert
        response = self.client.get("/train/iot")
        assert response.status_code == 405  # Method Not Allowed
        
        response = self.client.put("/train/iot")
        assert response.status_code == 405
        
        response = self.client.delete("/train/iot")
        assert response.status_code == 405
    
    def test_train_iot_model_from_kaggle_wrong_method(self):
        """Test que el endpoint de entrenamiento desde Kaggle solo acepta POST."""
        # Act & Assert
        response = self.client.get("/train/iot/kaggle")
        assert response.status_code == 405  # Method Not Allowed
        
        response = self.client.put("/train/iot/kaggle")
        assert response.status_code == 405
        
        response = self.client.delete("/train/iot/kaggle")
        assert response.status_code == 405
    
    def test_train_iot_model_response_model(self):
        """Test que la respuesta del entrenamiento sigue el modelo correcto."""
        # Arrange
        request_data = {
            "logs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "device_id": "device_001",
                    "device_type": "thermostat",
                    "cpu_usage": 50.0,
                    "memory_usage": 60.0,
                    "network_in_kb": 1000,
                    "network_out_kb": 500,
                    "packet_rate": 100,
                    "avg_response_time_ms": 50.0,
                    "service_access_count": 10,
                    "failed_auth_attempts": 0,
                    "is_encrypted": 1,
                    "geo_location_variation": 0.1,
                    "label": "normal"
                }
            ]
        }
        
        expected_response = TrainResponseDTO(
            status="trained",
            samples=1,
            file_path="models/isoforest.joblib",
            features=11
        )
        
        self.mock_train_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.post("/train/iot", json=request_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        
        # Verificar que todos los campos requeridos están presentes
        required_fields = ["status", "samples", "file_path", "features"]
        for field in required_fields:
            assert field in data
        
        # Verificar tipos de datos
        assert isinstance(data["status"], str)
        assert isinstance(data["samples"], int)
        assert isinstance(data["file_path"], str)
        assert isinstance(data["features"], int)
    
    def test_train_iot_model_from_kaggle_response_model(self):
        """Test que la respuesta del entrenamiento desde Kaggle sigue el modelo correcto."""
        # Arrange
        expected_response = TrainResponseDTO(
            status="trained_from_kaggle",
            samples=1000,
            file_path="models/isoforest.joblib",
            features=11
        )
        
        self.mock_train_from_kaggle_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.post("/train/iot/kaggle")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        
        # Verificar que todos los campos requeridos están presentes
        required_fields = ["status", "samples", "file_path", "features"]
        for field in required_fields:
            assert field in data
        
        # Verificar tipos de datos
        assert isinstance(data["status"], str)
        assert isinstance(data["samples"], int)
        assert isinstance(data["file_path"], str)
        assert isinstance(data["features"], int)
