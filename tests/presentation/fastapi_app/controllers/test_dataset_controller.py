"""
Tests para el controlador de dataset.

Estos tests verifican los endpoints de información y muestras del dataset.
"""

import pytest
from unittest.mock import Mock
from fastapi.testclient import TestClient
from src.presentation.fastapi_app.controllers.dataset_controller import DatasetController
from src.application.use_cases.get_dataset_info import GetDatasetInfoUseCase
from src.application.use_cases.get_dataset_sample import GetDatasetSampleUseCase
from src.domain.entities.dto import DatasetInfoDTO, DatasetSampleDTO


class TestDatasetController:
    """Tests para DatasetController."""
    
    def setup_method(self):
        """Setup para cada test."""
        self.mock_get_info_use_case = Mock(spec=GetDatasetInfoUseCase)
        self.mock_get_sample_use_case = Mock(spec=GetDatasetSampleUseCase)
        self.controller = DatasetController(
            self.mock_get_info_use_case,
            self.mock_get_sample_use_case
        )
        self.client = TestClient(self.controller.get_router())
    
    def test_get_dataset_info_success(self):
        """Test obtención exitosa de información del dataset."""
        # Arrange
        expected_response = DatasetInfoDTO(
            total_rows=10000,
            labeled_rows=2000,
            unlabeled_rows=8000,
            columns=["timestamp", "device_id", "cpu_usage", "memory_usage"],
            label_distribution={"normal": 1500, "anomaly": 500},
            device_type_distribution={"thermostat": 1000, "sensor": 1000},
            anomaly_ratio=0.25
        )
        
        self.mock_get_info_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.get("/dataset/info")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["total_rows"] == 10000
        assert data["labeled_rows"] == 2000
        assert data["unlabeled_rows"] == 8000
        assert len(data["columns"]) == 4
        assert data["columns"] == ["timestamp", "device_id", "cpu_usage", "memory_usage"]
        assert data["label_distribution"]["normal"] == 1500
        assert data["label_distribution"]["anomaly"] == 500
        assert data["device_type_distribution"]["thermostat"] == 1000
        assert data["device_type_distribution"]["sensor"] == 1000
        assert data["anomaly_ratio"] == 0.25
        
        # Verificar que se llamó al caso de uso
        self.mock_get_info_use_case.execute.assert_called_once()
    
    def test_get_dataset_info_file_not_found(self):
        """Test obtención de información cuando el archivo no existe."""
        # Arrange
        self.mock_get_info_use_case.execute.side_effect = FileNotFoundError("Dataset no encontrado")
        
        # Act
        response = self.client.get("/dataset/info")
        
        # Assert
        assert response.status_code == 404
        data = response.json()
        assert "Dataset no encontrado" in data["detail"]
    
    def test_get_dataset_info_use_case_exception(self):
        """Test obtención de información cuando el caso de uso lanza una excepción."""
        # Arrange
        self.mock_get_info_use_case.execute.side_effect = Exception("Error obteniendo información del dataset")
        
        # Act
        response = self.client.get("/dataset/info")
        
        # Assert
        assert response.status_code == 500
        data = response.json()
        assert "Error obteniendo información del dataset" in data["detail"]
    
    def test_get_dataset_sample_success_default_size(self):
        """Test obtención exitosa de muestra con tamaño por defecto."""
        # Arrange
        expected_response = DatasetSampleDTO(
            sample_size=10,
            total_rows=1000,
            data=[
                {"device_id": "device_001", "cpu_usage": 50.0, "label": "normal"},
                {"device_id": "device_002", "cpu_usage": 75.0, "label": "anomaly"}
            ]
        )
        
        self.mock_get_sample_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.get("/dataset/sample")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["sample_size"] == 10
        assert data["total_rows"] == 1000
        assert len(data["data"]) == 2
        assert data["data"][0]["device_id"] == "device_001"
        assert data["data"][0]["cpu_usage"] == 50.0
        assert data["data"][0]["label"] == "normal"
        assert data["data"][1]["device_id"] == "device_002"
        assert data["data"][1]["cpu_usage"] == 75.0
        assert data["data"][1]["label"] == "anomaly"
        
        # Verificar que se llamó al caso de uso con tamaño por defecto
        self.mock_get_sample_use_case.execute.assert_called_once_with(10)
    
    def test_get_dataset_sample_success_custom_size(self):
        """Test obtención exitosa de muestra con tamaño personalizado."""
        # Arrange
        expected_response = DatasetSampleDTO(
            sample_size=25,
            total_rows=1000,
            data=[{"device_id": f"device_{i:03d}", "cpu_usage": i * 2.0} for i in range(25)]
        )
        
        self.mock_get_sample_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.get("/dataset/sample?size=25")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["sample_size"] == 25
        assert data["total_rows"] == 1000
        assert len(data["data"]) == 25
        
        # Verificar que se llamó al caso de uso con tamaño personalizado
        self.mock_get_sample_use_case.execute.assert_called_once_with(25)
    
    def test_get_dataset_sample_size_limit(self):
        """Test que se respeta el límite máximo de tamaño."""
        # Arrange
        expected_response = DatasetSampleDTO(
            sample_size=100,  # Limitado a 100
            total_rows=1000,
            data=[{"device_id": f"device_{i:03d}"} for i in range(100)]
        )
        
        self.mock_get_sample_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.get("/dataset/sample?size=150")  # Mayor al límite
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["sample_size"] == 100  # Limitado a 100
        assert data["total_rows"] == 1000
        assert len(data["data"]) == 100
        
        # Verificar que se llamó al caso de uso con tamaño limitado
        self.mock_get_sample_use_case.execute.assert_called_once_with(100)
    
    def test_get_dataset_sample_file_not_found(self):
        """Test obtención de muestra cuando el archivo no existe."""
        # Arrange
        self.mock_get_sample_use_case.execute.side_effect = FileNotFoundError("Dataset no encontrado")
        
        # Act
        response = self.client.get("/dataset/sample")
        
        # Assert
        assert response.status_code == 404
        data = response.json()
        assert "Dataset no encontrado" in data["detail"]
    
    def test_get_dataset_sample_use_case_exception(self):
        """Test obtención de muestra cuando el caso de uso lanza una excepción."""
        # Arrange
        self.mock_get_sample_use_case.execute.side_effect = Exception("Error obteniendo muestra")
        
        # Act
        response = self.client.get("/dataset/sample")
        
        # Assert
        assert response.status_code == 500
        data = response.json()
        assert "Error obteniendo muestra" in data["detail"]
    
    def test_get_dataset_info_wrong_method(self):
        """Test que el endpoint de información solo acepta GET."""
        # Act & Assert
        response = self.client.post("/dataset/info")
        assert response.status_code == 405  # Method Not Allowed
        
        response = self.client.put("/dataset/info")
        assert response.status_code == 405
        
        response = self.client.delete("/dataset/info")
        assert response.status_code == 405
    
    def test_get_dataset_sample_wrong_method(self):
        """Test que el endpoint de muestra solo acepta GET."""
        # Act & Assert
        response = self.client.post("/dataset/sample")
        assert response.status_code == 405  # Method Not Allowed
        
        response = self.client.put("/dataset/sample")
        assert response.status_code == 405
        
        response = self.client.delete("/dataset/sample")
        assert response.status_code == 405
    
    def test_get_dataset_info_response_model(self):
        """Test que la respuesta de información sigue el modelo correcto."""
        # Arrange
        expected_response = DatasetInfoDTO(
            total_rows=1000,
            labeled_rows=200,
            unlabeled_rows=800,
            columns=["timestamp", "device_id", "cpu_usage"],
            label_distribution={"normal": 150, "anomaly": 50},
            device_type_distribution={"thermostat": 100, "sensor": 100},
            anomaly_ratio=0.25
        )
        
        self.mock_get_info_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.get("/dataset/info")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        
        # Verificar que todos los campos requeridos están presentes
        required_fields = ["total_rows", "labeled_rows", "unlabeled_rows", "columns", 
                          "label_distribution", "device_type_distribution", "anomaly_ratio"]
        for field in required_fields:
            assert field in data
        
        # Verificar tipos de datos
        assert isinstance(data["total_rows"], int)
        assert isinstance(data["labeled_rows"], int)
        assert isinstance(data["unlabeled_rows"], int)
        assert isinstance(data["columns"], list)
        assert isinstance(data["label_distribution"], dict)
        assert isinstance(data["device_type_distribution"], dict)
        assert isinstance(data["anomaly_ratio"], (int, float))
    
    def test_get_dataset_sample_response_model(self):
        """Test que la respuesta de muestra sigue el modelo correcto."""
        # Arrange
        expected_response = DatasetSampleDTO(
            sample_size=5,
            total_rows=100,
            data=[
                {"device_id": "device_001", "cpu_usage": 50.0},
                {"device_id": "device_002", "cpu_usage": 75.0}
            ]
        )
        
        self.mock_get_sample_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.get("/dataset/sample?size=5")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        
        # Verificar que todos los campos requeridos están presentes
        required_fields = ["sample_size", "total_rows", "data"]
        for field in required_fields:
            assert field in data
        
        # Verificar tipos de datos
        assert isinstance(data["sample_size"], int)
        assert isinstance(data["total_rows"], int)
        assert isinstance(data["data"], list)
        
        # Verificar que data contiene diccionarios
        for item in data["data"]:
            assert isinstance(item, dict)
    
    def test_get_dataset_sample_invalid_size_parameter(self):
        """Test obtención de muestra con parámetro de tamaño inválido."""
        # Act
        response = self.client.get("/dataset/sample?size=invalid")
        
        # Assert
        assert response.status_code == 422  # Validation Error
        data = response.json()
        assert "detail" in data
    
    def test_get_dataset_sample_negative_size_parameter(self):
        """Test obtención de muestra con parámetro de tamaño negativo."""
        # Act
        response = self.client.get("/dataset/sample?size=-5")
        
        # Assert
        assert response.status_code == 422  # Validation Error
        data = response.json()
        assert "detail" in data
