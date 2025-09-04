"""
Tests para el controlador de análisis.

Estos tests verifican los endpoints de análisis de logs IoT.
"""

import pytest
from unittest.mock import Mock
from fastapi.testclient import TestClient
from fastapi import HTTPException
from src.presentation.fastapi_app.controllers.analysis_controller import AnalysisController
from src.application.use_cases.analyze_iot_logs import AnalyzeIoTLogsUseCase
from src.domain.entities.dto import IoTAnalyzeRequestDTO, IoTAnalyzeResponseDTO, IoTLogItemDTO


class TestAnalysisController:
    """Tests para AnalysisController."""
    
    def setup_method(self):
        """Setup para cada test."""
        self.mock_use_case = Mock(spec=AnalyzeIoTLogsUseCase)
        self.controller = AnalysisController(self.mock_use_case)
        self.client = TestClient(self.controller.get_router())
    
    def test_analyze_iot_batch_success(self):
        """Test análisis exitoso de logs IoT."""
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
        
        expected_response = IoTAnalyzeResponseDTO(
            trace_id="trace_123",
            score=0.85,
            decision={"action": "block", "confidence": 0.9},
            batch_size=1
        )
        
        self.mock_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.post("/analyze", json=request_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["trace_id"] == "trace_123"
        assert data["score"] == 0.85
        assert data["decision"]["action"] == "block"
        assert data["decision"]["confidence"] == 0.9
        assert data["batch_size"] == 1
        
        # Verificar que se llamó al caso de uso
        self.mock_use_case.execute.assert_called_once()
        call_args = self.mock_use_case.execute.call_args[0][0]
        assert isinstance(call_args, IoTAnalyzeRequestDTO)
        assert len(call_args.logs) == 1
        assert call_args.logs[0].device_id == "device_001"
    
    def test_analyze_iot_batch_empty_logs(self):
        """Test análisis con lista vacía de logs."""
        # Arrange
        request_data = {"logs": []}
        
        expected_response = IoTAnalyzeResponseDTO(
            trace_id="trace_123",
            score=0.0,
            decision={},
            batch_size=0
        )
        
        self.mock_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.post("/analyze", json=request_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["trace_id"] == "trace_123"
        assert data["score"] == 0.0
        assert data["decision"] == {}
        assert data["batch_size"] == 0
    
    def test_analyze_iot_batch_multiple_logs(self):
        """Test análisis con múltiples logs."""
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
        
        expected_response = IoTAnalyzeResponseDTO(
            trace_id="trace_456",
            score=0.75,
            decision={"action": "monitor", "confidence": 0.8},
            batch_size=2
        )
        
        self.mock_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.post("/analyze", json=request_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["trace_id"] == "trace_456"
        assert data["score"] == 0.75
        assert data["decision"]["action"] == "monitor"
        assert data["batch_size"] == 2
        
        # Verificar que se llamó al caso de uso con 2 logs
        self.mock_use_case.execute.assert_called_once()
        call_args = self.mock_use_case.execute.call_args[0][0]
        assert len(call_args.logs) == 2
        assert call_args.logs[0].device_id == "device_001"
        assert call_args.logs[1].device_id == "device_002"
    
    def test_analyze_iot_batch_validation_error(self):
        """Test análisis con datos de validación inválidos."""
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
        response = self.client.post("/analyze", json=request_data)
        
        # Assert
        assert response.status_code == 422  # Validation Error
        data = response.json()
        assert "detail" in data
    
    def test_analyze_iot_batch_missing_required_fields(self):
        """Test análisis con campos requeridos faltantes."""
        # Arrange
        request_data = {
            "logs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "device_id": "device_001",
                    # Faltan campos requeridos
                }
            ]
        }
        
        # Act
        response = self.client.post("/analyze", json=request_data)
        
        # Assert
        assert response.status_code == 422  # Validation Error
        data = response.json()
        assert "detail" in data
    
    def test_analyze_iot_batch_use_case_exception(self):
        """Test análisis cuando el caso de uso lanza una excepción."""
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
        
        self.mock_use_case.execute.side_effect = Exception("Error en análisis")
        
        # Act
        response = self.client.post("/analyze", json=request_data)
        
        # Assert
        assert response.status_code == 500
        data = response.json()
        assert "Error en análisis" in data["detail"]
    
    def test_analyze_iot_batch_wrong_method(self):
        """Test que el endpoint solo acepta POST."""
        # Act & Assert
        response = self.client.get("/analyze")
        assert response.status_code == 405  # Method Not Allowed
        
        response = self.client.put("/analyze")
        assert response.status_code == 405
        
        response = self.client.delete("/analyze")
        assert response.status_code == 405
    
    def test_analyze_iot_batch_invalid_json(self):
        """Test análisis con JSON inválido."""
        # Act
        response = self.client.post(
            "/analyze",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        
        # Assert
        assert response.status_code == 422  # Validation Error
    
    def test_analyze_iot_batch_empty_request(self):
        """Test análisis con request vacío."""
        # Act
        response = self.client.post("/analyze", json={})
        
        # Assert
        assert response.status_code == 422  # Validation Error
        data = response.json()
        assert "detail" in data
    
    def test_analyze_iot_batch_response_model(self):
        """Test que la respuesta sigue el modelo correcto."""
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
        
        expected_response = IoTAnalyzeResponseDTO(
            trace_id="trace_123",
            score=0.85,
            decision={"action": "block", "confidence": 0.9},
            batch_size=1
        )
        
        self.mock_use_case.execute.return_value = expected_response
        
        # Act
        response = self.client.post("/analyze", json=request_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        
        # Verificar que todos los campos requeridos están presentes
        required_fields = ["trace_id", "score", "decision", "batch_size"]
        for field in required_fields:
            assert field in data
        
        # Verificar tipos de datos
        assert isinstance(data["trace_id"], str)
        assert isinstance(data["score"], (int, float))
        assert isinstance(data["decision"], dict)
        assert isinstance(data["batch_size"], int)
