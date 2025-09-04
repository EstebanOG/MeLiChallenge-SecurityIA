"""
Tests para el controlador de salud.

Estos tests verifican los endpoints de salud e información del sistema.
"""

import pytest
from fastapi.testclient import TestClient
from src.presentation.fastapi_app.controllers.health_controller import router


class TestHealthController:
    """Tests para HealthController."""
    
    def setup_method(self):
        """Setup para cada test."""
        self.client = TestClient(router)
    
    def test_health_endpoint(self):
        """Test endpoint de salud del sistema."""
        # Act
        response = self.client.get("/health")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["dataset"] == "IoT Anomaly Detection"
    
    def test_info_endpoint(self):
        """Test endpoint de información del proyecto."""
        # Act
        response = self.client.get("/")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["project"] == "IoT Anomaly Detection API"
        assert data["version"] == "2.0.0"
        assert data["description"] == "API para detección de anomalías en dispositivos IoT"
        assert isinstance(data["features"], list)
        assert len(data["features"]) == 4
        assert "Detección de anomalías en tiempo real" in data["features"]
        assert "Análisis de métricas de dispositivos IoT" in data["features"]
        assert "Modelo Isolation Forest adaptado" in data["features"]
        assert "Pipeline de agentes LangGraph" in data["features"]
        assert isinstance(data["supported_device_types"], list)
        assert len(data["supported_device_types"]) == 8
        assert "thermostat" in data["supported_device_types"]
        assert "smart" in data["supported_device_types"]
        assert "sensor" in data["supported_device_types"]
        assert "camera" in data["supported_device_types"]
        assert "lock" in data["supported_device_types"]
        assert "hub" in data["supported_device_types"]
        assert "appliance" in data["supported_device_types"]
        assert "wearable" in data["supported_device_types"]
    
    def test_health_response_model(self):
        """Test que la respuesta del endpoint de salud sigue el modelo correcto."""
        # Act
        response = self.client.get("/health")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        
        # Verificar que todos los campos requeridos están presentes
        required_fields = ["status", "dataset"]
        for field in required_fields:
            assert field in data
        
        # Verificar tipos de datos
        assert isinstance(data["status"], str)
        assert isinstance(data["dataset"], str)
    
    def test_info_response_model(self):
        """Test que la respuesta del endpoint de información sigue el modelo correcto."""
        # Act
        response = self.client.get("/")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        
        # Verificar que todos los campos requeridos están presentes
        required_fields = ["project", "version", "description", "features", "supported_device_types"]
        for field in required_fields:
            assert field in data
        
        # Verificar tipos de datos
        assert isinstance(data["project"], str)
        assert isinstance(data["version"], str)
        assert isinstance(data["description"], str)
        assert isinstance(data["features"], list)
        assert isinstance(data["supported_device_types"], list)
        
        # Verificar que features contiene strings
        for feature in data["features"]:
            assert isinstance(feature, str)
        
        # Verificar que supported_device_types contiene strings
        for device_type in data["supported_device_types"]:
            assert isinstance(device_type, str)
    
    def test_health_endpoint_methods(self):
        """Test que el endpoint de salud solo acepta GET."""
        # Act & Assert
        response = self.client.post("/health")
        assert response.status_code == 405  # Method Not Allowed
        
        response = self.client.put("/health")
        assert response.status_code == 405
        
        response = self.client.delete("/health")
        assert response.status_code == 405
    
    def test_info_endpoint_methods(self):
        """Test que el endpoint de información solo acepta GET."""
        # Act & Assert
        response = self.client.post("/")
        assert response.status_code == 405  # Method Not Allowed
        
        response = self.client.put("/")
        assert response.status_code == 405
        
        response = self.client.delete("/")
        assert response.status_code == 405
    
    def test_health_endpoint_headers(self):
        """Test que el endpoint de salud retorna headers correctos."""
        # Act
        response = self.client.get("/health")
        
        # Assert
        assert response.status_code == 200
        assert "content-type" in response.headers
        assert "application/json" in response.headers["content-type"]
    
    def test_info_endpoint_headers(self):
        """Test que el endpoint de información retorna headers correctos."""
        # Act
        response = self.client.get("/")
        
        # Assert
        assert response.status_code == 200
        assert "content-type" in response.headers
        assert "application/json" in response.headers["content-type"]
