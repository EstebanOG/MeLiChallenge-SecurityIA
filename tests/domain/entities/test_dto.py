"""
Tests para DTOs del dominio.

Estos tests verifican la validación y comportamiento de los DTOs
usados para comunicación entre capas.
"""

import pytest
from pydantic import ValidationError
from src.domain.entities.dto import (
    IoTLogItemDTO,
    IoTAnalyzeRequestDTO,
    IoTAnalyzeResponseDTO,
    TrainRequestDTO,
    TrainResponseDTO,
    DatasetInfoDTO,
    DatasetSampleDTO,
    HealthResponseDTO,
    InfoResponseDTO,
    ErrorResponseDTO
)


class TestIoTLogItemDTO:
    """Tests para IoTLogItemDTO."""
    
    def test_valid_iot_log_item(self):
        """Test que un item válido se crea correctamente."""
        item = IoTLogItemDTO(
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
        
        assert item.timestamp == "2024-01-01T00:00:00Z"
        assert item.device_id == "device_001"
        assert item.device_type == "thermostat"
        assert item.cpu_usage == 50.0
        assert item.label == "normal"
    
    def test_cpu_usage_validation(self):
        """Test validación de cpu_usage."""
        # CPU usage válido
        item = IoTLogItemDTO(
            timestamp="2024-01-01T00:00:00Z",
            device_id="device_001",
            device_type="thermostat",
            cpu_usage=0.0,
            memory_usage=60.0,
            network_in_kb=1000,
            network_out_kb=500,
            packet_rate=100,
            avg_response_time_ms=50.0,
            service_access_count=10,
            failed_auth_attempts=0,
            is_encrypted=1,
            geo_location_variation=0.1
        )
        assert item.cpu_usage == 0.0
        
        # CPU usage inválido (negativo)
        with pytest.raises(ValidationError):
            IoTLogItemDTO(
                timestamp="2024-01-01T00:00:00Z",
                device_id="device_001",
                device_type="thermostat",
                cpu_usage=-1.0,
                memory_usage=60.0,
                network_in_kb=1000,
                network_out_kb=500,
                packet_rate=100,
                avg_response_time_ms=50.0,
                service_access_count=10,
                failed_auth_attempts=0,
                is_encrypted=1,
                geo_location_variation=0.1
            )
        
        # CPU usage inválido (mayor a 100)
        with pytest.raises(ValidationError):
            IoTLogItemDTO(
                timestamp="2024-01-01T00:00:00Z",
                device_id="device_001",
                device_type="thermostat",
                cpu_usage=101.0,
                memory_usage=60.0,
                network_in_kb=1000,
                network_out_kb=500,
                packet_rate=100,
                avg_response_time_ms=50.0,
                service_access_count=10,
                failed_auth_attempts=0,
                is_encrypted=1,
                geo_location_variation=0.1
            )
    
    def test_network_validation(self):
        """Test validación de campos de red."""
        # Valores válidos
        item = IoTLogItemDTO(
            timestamp="2024-01-01T00:00:00Z",
            device_id="device_001",
            device_type="thermostat",
            cpu_usage=50.0,
            memory_usage=60.0,
            network_in_kb=0,
            network_out_kb=0,
            packet_rate=0,
            avg_response_time_ms=0.0,
            service_access_count=0,
            failed_auth_attempts=0,
            is_encrypted=0,
            geo_location_variation=0.0
        )
        assert item.network_in_kb == 0
        
        # Valores inválidos (negativos)
        with pytest.raises(ValidationError):
            IoTLogItemDTO(
                timestamp="2024-01-01T00:00:00Z",
                device_id="device_001",
                device_type="thermostat",
                cpu_usage=50.0,
                memory_usage=60.0,
                network_in_kb=-1,
                network_out_kb=500,
                packet_rate=100,
                avg_response_time_ms=50.0,
                service_access_count=10,
                failed_auth_attempts=0,
                is_encrypted=1,
                geo_location_variation=0.1
            )
    
    def test_is_encrypted_validation(self):
        """Test validación de is_encrypted."""
        # Valores válidos
        for value in [0, 1]:
            item = IoTLogItemDTO(
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
                is_encrypted=value,
                geo_location_variation=0.1
            )
            assert item.is_encrypted == value
        
        # Valores inválidos
        for value in [-1, 2, 1.5]:
            with pytest.raises(ValidationError):
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
                    is_encrypted=value,
                    geo_location_variation=0.1
                )


class TestIoTAnalyzeRequestDTO:
    """Tests para IoTAnalyzeRequestDTO."""
    
    def test_valid_request(self):
        """Test que una request válida se crea correctamente."""
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
            geo_location_variation=0.1
        )
        
        request = IoTAnalyzeRequestDTO(logs=[log_item])
        assert len(request.logs) == 1
        assert request.logs[0].device_id == "device_001"
    
    def test_empty_logs_list(self):
        """Test que se puede crear una request con lista vacía."""
        request = IoTAnalyzeRequestDTO(logs=[])
        assert len(request.logs) == 0


class TestIoTAnalyzeResponseDTO:
    """Tests para IoTAnalyzeResponseDTO."""
    
    def test_valid_response(self):
        """Test que una response válida se crea correctamente."""
        response = IoTAnalyzeResponseDTO(
            trace_id="trace_123",
            score=0.85,
            decision={"action": "block", "confidence": 0.9},
            batch_size=10
        )
        
        assert response.trace_id == "trace_123"
        assert response.score == 0.85
        assert response.decision["action"] == "block"
        assert response.batch_size == 10


class TestTrainResponseDTO:
    """Tests para TrainResponseDTO."""
    
    def test_valid_train_response(self):
        """Test que una response de entrenamiento válida se crea correctamente."""
        response = TrainResponseDTO(
            status="trained",
            samples=1000,
            file_path="models/isoforest.joblib",
            features=11
        )
        
        assert response.status == "trained"
        assert response.samples == 1000
        assert response.file_path == "models/isoforest.joblib"
        assert response.features == 11


class TestDatasetInfoDTO:
    """Tests para DatasetInfoDTO."""
    
    def test_valid_dataset_info(self):
        """Test que la información del dataset se crea correctamente."""
        info = DatasetInfoDTO(
            total_rows=10000,
            labeled_rows=2000,
            unlabeled_rows=8000,
            columns=["timestamp", "device_id", "cpu_usage"],
            label_distribution={"normal": 1500, "anomaly": 500},
            device_type_distribution={"thermostat": 1000, "sensor": 1000},
            anomaly_ratio=0.25
        )
        
        assert info.total_rows == 10000
        assert info.labeled_rows == 2000
        assert info.unlabeled_rows == 8000
        assert len(info.columns) == 3
        assert info.label_distribution["normal"] == 1500
        assert info.anomaly_ratio == 0.25


class TestDatasetSampleDTO:
    """Tests para DatasetSampleDTO."""
    
    def test_valid_dataset_sample(self):
        """Test que una muestra del dataset se crea correctamente."""
        sample = DatasetSampleDTO(
            sample_size=10,
            total_rows=1000,
            data=[
                {"device_id": "device_001", "cpu_usage": 50.0},
                {"device_id": "device_002", "cpu_usage": 75.0}
            ]
        )
        
        assert sample.sample_size == 10
        assert sample.total_rows == 1000
        assert len(sample.data) == 2
        assert sample.data[0]["device_id"] == "device_001"


class TestHealthResponseDTO:
    """Tests para HealthResponseDTO."""
    
    def test_valid_health_response(self):
        """Test que una response de salud se crea correctamente."""
        response = HealthResponseDTO(
            status="ok",
            dataset="IoT Anomaly Detection"
        )
        
        assert response.status == "ok"
        assert response.dataset == "IoT Anomaly Detection"


class TestInfoResponseDTO:
    """Tests para InfoResponseDTO."""
    
    def test_valid_info_response(self):
        """Test que una response de información se crea correctamente."""
        response = InfoResponseDTO(
            project="IoT Anomaly Detection API",
            version="2.0.0",
            description="API para detección de anomalías",
            features=["Detección en tiempo real", "Análisis de métricas"],
            supported_device_types=["thermostat", "sensor"]
        )
        
        assert response.project == "IoT Anomaly Detection API"
        assert response.version == "2.0.0"
        assert len(response.features) == 2
        assert len(response.supported_device_types) == 2


class TestErrorResponseDTO:
    """Tests para ErrorResponseDTO."""
    
    def test_valid_error_response(self):
        """Test que una response de error se crea correctamente."""
        error = ErrorResponseDTO(
            error_code="VALIDATION_ERROR",
            message="Error de validación",
            details={"field": "cpu_usage", "value": -1},
            trace_id="trace_123"
        )
        
        assert error.error_code == "VALIDATION_ERROR"
        assert error.message == "Error de validación"
        assert error.details["field"] == "cpu_usage"
        assert error.trace_id == "trace_123"
    
    def test_error_response_without_optional_fields(self):
        """Test que se puede crear error response sin campos opcionales."""
        error = ErrorResponseDTO(
            error_code="INTERNAL_ERROR",
            message="Error interno"
        )
        
        assert error.error_code == "INTERNAL_ERROR"
        assert error.message == "Error interno"
        assert error.details is None
        assert error.trace_id is None
