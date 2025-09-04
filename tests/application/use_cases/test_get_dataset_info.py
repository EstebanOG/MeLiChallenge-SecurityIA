"""
Tests para el caso de uso GetDatasetInfoUseCase.

Estos tests verifican la lógica de negocio para obtener información del dataset.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open
from src.application.use_cases.get_dataset_info import GetDatasetInfoUseCase
from src.domain.entities.dto import DatasetInfoDTO


class TestGetDatasetInfoUseCase:
    """Tests para GetDatasetInfoUseCase."""
    
    def setup_method(self):
        """Setup para cada test."""
        self.use_case = GetDatasetInfoUseCase()
    
    def test_execute_success(self):
        """Test ejecución exitosa obteniendo información del dataset."""
        # Arrange
        mock_info = {
            "total_rows": 10000,
            "labeled_rows": 2000,
            "unlabeled_rows": 8000,
            "columns": ["timestamp", "device_id", "cpu_usage", "memory_usage"],
            "label_distribution": {"normal": 1500, "anomaly": 500},
            "device_type_distribution": {"thermostat": 1000, "sensor": 1000},
            "anomaly_ratio": 0.25
        }
        
        mock_file_content = json.dumps(mock_info)
        
        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            with patch("pathlib.Path.exists", return_value=True):
                # Act
                result = self.use_case.execute()
        
        # Assert
        assert isinstance(result, DatasetInfoDTO)
        assert result.total_rows == 10000
        assert result.labeled_rows == 2000
        assert result.unlabeled_rows == 8000
        assert len(result.columns) == 4
        assert result.columns == ["timestamp", "device_id", "cpu_usage", "memory_usage"]
        assert result.label_distribution["normal"] == 1500
        assert result.label_distribution["anomaly"] == 500
        assert result.device_type_distribution["thermostat"] == 1000
        assert result.device_type_distribution["sensor"] == 1000
        assert result.anomaly_ratio == 0.25
    
    def test_execute_file_not_found(self):
        """Test ejecución cuando el archivo no existe."""
        # Arrange
        with patch("pathlib.Path.exists", return_value=False):
            # Act & Assert
            with pytest.raises(FileNotFoundError) as exc_info:
                self.use_case.execute()
            
            assert "Dataset no encontrado" in str(exc_info.value)
            assert "Ejecuta /train/iot/kaggle primero" in str(exc_info.value)
    
    def test_execute_invalid_json(self):
        """Test ejecución con JSON inválido."""
        # Arrange
        invalid_json = "{ invalid json content }"
        
        with patch("builtins.open", mock_open(read_data=invalid_json)):
            with patch("pathlib.Path.exists", return_value=True):
                # Act & Assert
                with pytest.raises(json.JSONDecodeError):
                    self.use_case.execute()
    
    def test_execute_missing_required_fields(self):
        """Test ejecución con campos requeridos faltantes."""
        # Arrange
        incomplete_info = {
            "total_rows": 10000,
            "labeled_rows": 2000,
            # Faltan campos requeridos
        }
        
        mock_file_content = json.dumps(incomplete_info)
        
        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            with patch("pathlib.Path.exists", return_value=True):
                # Act & Assert
                with pytest.raises(ValueError):  # Pydantic validation error
                    self.use_case.execute()
    
    def test_execute_with_empty_dataset(self):
        """Test ejecución con dataset vacío."""
        # Arrange
        empty_info = {
            "total_rows": 0,
            "labeled_rows": 0,
            "unlabeled_rows": 0,
            "columns": [],
            "label_distribution": {},
            "device_type_distribution": {},
            "anomaly_ratio": 0.0
        }
        
        mock_file_content = json.dumps(empty_info)
        
        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            with patch("pathlib.Path.exists", return_value=True):
                # Act
                result = self.use_case.execute()
        
        # Assert
        assert isinstance(result, DatasetInfoDTO)
        assert result.total_rows == 0
        assert result.labeled_rows == 0
        assert result.unlabeled_rows == 0
        assert len(result.columns) == 0
        assert len(result.label_distribution) == 0
        assert len(result.device_type_distribution) == 0
        assert result.anomaly_ratio == 0.0
    
    def test_execute_with_large_dataset(self):
        """Test ejecución con dataset grande."""
        # Arrange
        large_info = {
            "total_rows": 1000000,
            "labeled_rows": 200000,
            "unlabeled_rows": 800000,
            "columns": ["timestamp", "device_id", "device_type", "cpu_usage", 
                       "memory_usage", "network_in_kb", "network_out_kb", 
                       "packet_rate", "avg_response_time_ms", "service_access_count",
                       "failed_auth_attempts", "is_encrypted", "geo_location_variation", "label"],
            "label_distribution": {
                "normal": 150000,
                "anomaly": 50000,
                "suspicious": 10000,
                "unknown": 5000
            },
            "device_type_distribution": {
                "thermostat": 50000,
                "sensor": 50000,
                "camera": 30000,
                "smart_lock": 20000,
                "hub": 10000,
                "appliance": 15000,
                "wearable": 25000
            },
            "anomaly_ratio": 0.25
        }
        
        mock_file_content = json.dumps(large_info)
        
        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            with patch("pathlib.Path.exists", return_value=True):
                # Act
                result = self.use_case.execute()
        
        # Assert
        assert isinstance(result, DatasetInfoDTO)
        assert result.total_rows == 1000000
        assert result.labeled_rows == 200000
        assert result.unlabeled_rows == 800000
        assert len(result.columns) == 14
        assert len(result.label_distribution) == 4
        assert len(result.device_type_distribution) == 7
        assert result.anomaly_ratio == 0.25
    
    def test_execute_with_float_values(self):
        """Test ejecución con valores float en distribuciones."""
        # Arrange
        float_info = {
            "total_rows": 1000,
            "labeled_rows": 200,
            "unlabeled_rows": 800,
            "columns": ["timestamp", "device_id", "cpu_usage"],
            "label_distribution": {"normal": 150.5, "anomaly": 49.5},
            "device_type_distribution": {"thermostat": 100.0, "sensor": 100.0},
            "anomaly_ratio": 0.2475
        }
        
        mock_file_content = json.dumps(float_info)
        
        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            with patch("pathlib.Path.exists", return_value=True):
                # Act
                result = self.use_case.execute()
        
        # Assert
        assert isinstance(result, DatasetInfoDTO)
        assert result.label_distribution["normal"] == 150.5
        assert result.label_distribution["anomaly"] == 49.5
        assert result.device_type_distribution["thermostat"] == 100.0
        assert result.anomaly_ratio == 0.2475
