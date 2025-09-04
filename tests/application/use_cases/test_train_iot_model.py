"""
Tests para el caso de uso TrainIoTModelUseCase.

Estos tests verifican la lógica de negocio para entrenamiento del modelo IoT.
"""

import pytest
from unittest.mock import Mock, patch
from src.application.use_cases.train_iot_model import TrainIoTModelUseCase
from src.domain.entities.dto import TrainRequestDTO, IoTLogItemDTO
from src.domain.entities.log_entry import LogEntry


class TestTrainIoTModelUseCase:
    """Tests para TrainIoTModelUseCase."""
    
    def setup_method(self):
        """Setup para cada test."""
        self.mock_detector = Mock()
        self.use_case = TrainIoTModelUseCase(self.mock_detector)
    
    def test_execute_success(self):
        """Test ejecución exitosa del entrenamiento."""
        # Arrange
        log_item = IoTLogItemDTO(
            timestamp="2024-01-01T00:00:00Z",
            device_id="device_001",
            device_type="thermostat",
            cpu_usage=50.0,
            memory_usage=60.0,
            network_in_kb=1000,
            network_out_kb=500,
            packet_rate=100,
            avg_response_time_ms=50.0,
            service_access_count=10,
            failed_auth_attempts=0,
            is_encrypted=1,
            geo_location_variation=0.1,
            label="normal"
        )
        
        request = TrainRequestDTO(logs=[log_item])
        
        # Act
        result = self.use_case.execute(request)
        
        # Assert
        assert result.status == "trained"
        assert result.samples == 1
        assert result.file_path == "models/isoforest.joblib"
        assert result.features == 11
        
        # Verificar que se llamó al detector
        self.mock_detector.fit.assert_called_once()
        call_args = self.mock_detector.fit.call_args[0][0]
        assert len(call_args) == 1
        assert isinstance(call_args[0], LogEntry)
        assert call_args[0].device_id == "device_001"
        assert call_args[0].label == "normal"
    
    def test_execute_with_multiple_logs(self):
        """Test ejecución con múltiples logs."""
        # Arrange
        log_items = [
            IoTLogItemDTO(
                timestamp="2024-01-01T00:00:00Z",
                device_id="device_001",
                device_type="thermostat",
                cpu_usage=50.0,
                memory_usage=60.0,
                network_in_kb=1000,
                network_out_kb=500,
                packet_rate=100,
                avg_response_time_ms=50.0,
                service_access_count=10,
                failed_auth_attempts=0,
                is_encrypted=1,
                geo_location_variation=0.1,
                label="normal"
            ),
            IoTLogItemDTO(
                timestamp="2024-01-01T01:00:00Z",
                device_id="device_002",
                device_type="sensor",
                cpu_usage=75.0,
                memory_usage=80.0,
                network_in_kb=2000,
                network_out_kb=1000,
                packet_rate=200,
                avg_response_time_ms=100.0,
                service_access_count=20,
                failed_auth_attempts=1,
                is_encrypted=0,
                geo_location_variation=0.2,
                label="anomaly"
            )
        ]
        
        request = TrainRequestDTO(logs=log_items)
        
        # Act
        result = self.use_case.execute(request)
        
        # Assert
        assert result.status == "trained"
        assert result.samples == 2
        assert result.file_path == "models/isoforest.joblib"
        assert result.features == 11
        
        # Verificar que se llamó al detector con 2 logs
        self.mock_detector.fit.assert_called_once()
        call_args = self.mock_detector.fit.call_args[0][0]
        assert len(call_args) == 2
        assert all(isinstance(log, LogEntry) for log in call_args)
        assert call_args[0].device_id == "device_001"
        assert call_args[1].device_id == "device_002"
    
    def test_execute_with_empty_logs(self):
        """Test ejecución con lista vacía de logs."""
        # Arrange
        request = TrainRequestDTO(logs=[])
        
        # Act
        result = self.use_case.execute(request)
        
        # Assert
        assert result.status == "trained"
        assert result.samples == 0
        assert result.file_path == "models/isoforest.joblib"
        assert result.features == 11
        
        # Verificar que se llamó al detector con lista vacía
        self.mock_detector.fit.assert_called_once()
        call_args = self.mock_detector.fit.call_args[0][0]
        assert len(call_args) == 0
    
    def test_execute_with_none_label(self):
        """Test ejecución con logs que tienen label None."""
        # Arrange
        log_item = IoTLogItemDTO(
            timestamp="2024-01-01T00:00:00Z",
            device_id="device_001",
            device_type="thermostat",
            cpu_usage=50.0,
            memory_usage=60.0,
            network_in_kb=1000,
            network_out_kb=500,
            packet_rate=100,
            avg_response_time_ms=50.0,
            service_access_count=10,
            failed_auth_attempts=0,
            is_encrypted=1,
            geo_location_variation=0.1,
            label=None
        )
        
        request = TrainRequestDTO(logs=[log_item])
        
        # Act
        result = self.use_case.execute(request)
        
        # Assert
        assert result.status == "trained"
        assert result.samples == 1
        
        # Verificar que se creó LogEntry con label None
        self.mock_detector.fit.assert_called_once()
        call_args = self.mock_detector.fit.call_args[0][0]
        assert len(call_args) == 1
        assert call_args[0].label is None
    
    def test_convert_to_log_entries(self):
        """Test conversión de DTOs a LogEntry."""
        # Arrange
        log_item = IoTLogItemDTO(
            timestamp="2024-01-01T00:00:00Z",
            device_id="device_001",
            device_type="thermostat",
            cpu_usage=50.0,
            memory_usage=60.0,
            network_in_kb=1000,
            network_out_kb=500,
            packet_rate=100,
            avg_response_time_ms=50.0,
            service_access_count=10,
            failed_auth_attempts=0,
            is_encrypted=1,
            geo_location_variation=0.1,
            label="normal"
        )
        
        # Act
        result = self.use_case._convert_to_log_entries([log_item])
        
        # Assert
        assert len(result) == 1
        assert isinstance(result[0], LogEntry)
        assert result[0].timestamp == "2024-01-01T00:00:00Z"
        assert result[0].device_id == "device_001"
        assert result[0].device_type == "thermostat"
        assert result[0].cpu_usage == 50.0
        assert result[0].memory_usage == 60.0
        assert result[0].network_in_kb == 1000
        assert result[0].network_out_kb == 500
        assert result[0].packet_rate == 100
        assert result[0].avg_response_time_ms == 50.0
        assert result[0].service_access_count == 10
        assert result[0].failed_auth_attempts == 0
        assert result[0].is_encrypted == 1
        assert result[0].geo_location_variation == 0.1
        assert result[0].label == "normal"
    
    def test_convert_to_log_entries_with_none_values(self):
        """Test conversión con valores None."""
        # Arrange
        log_item = IoTLogItemDTO(
            timestamp="2024-01-01T00:00:00Z",
            device_id="device_001",
            device_type="thermostat",
            cpu_usage=0.0,
            memory_usage=0.0,
            network_in_kb=0,
            network_out_kb=0,
            packet_rate=0,
            avg_response_time_ms=0.0,
            service_access_count=0,
            failed_auth_attempts=0,
            is_encrypted=0,
            geo_location_variation=0.0,
            label=None
        )
        
        # Act
        result = self.use_case._convert_to_log_entries([log_item])
        
        # Assert
        assert len(result) == 1
        assert isinstance(result[0], LogEntry)
        assert result[0].cpu_usage == 0.0
        assert result[0].memory_usage == 0.0
        assert result[0].network_in_kb == 0
        assert result[0].label is None
