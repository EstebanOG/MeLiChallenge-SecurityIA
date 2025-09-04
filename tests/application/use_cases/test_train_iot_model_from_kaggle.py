"""
Tests para el caso de uso TrainIoTModelFromKaggleUseCase.

Estos tests verifican la lógica de negocio para entrenamiento del modelo
desde datos de Kaggle.
"""

import pytest
import pandas as pd
from unittest.mock import Mock, patch, MagicMock
from src.application.use_cases.train_iot_model_from_kaggle import TrainIoTModelFromKaggleUseCase
from src.domain.entities.log_entry import LogEntry


class TestTrainIoTModelFromKaggleUseCase:
    """Tests para TrainIoTModelFromKaggleUseCase."""
    
    def setup_method(self):
        """Setup para cada test."""
        self.mock_detector = Mock()
        self.mock_dataset_service = Mock()
        self.use_case = TrainIoTModelFromKaggleUseCase(
            self.mock_detector,
            self.mock_dataset_service
        )
    
    def test_execute_success(self):
        """Test ejecución exitosa del entrenamiento desde Kaggle."""
        # Arrange
        mock_df = pd.DataFrame({
            'timestamp': ['2024-01-01T00:00:00Z', '2024-01-01T01:00:00Z'],
            'device_id': ['device_001', 'device_002'],
            'device_type': ['thermostat', 'sensor'],
            'cpu_usage': [50.0, 75.0],
            'memory_usage': [60.0, 80.0],
            'network_in_kb': [1000, 2000],
            'network_out_kb': [500, 1000],
            'packet_rate': [100, 200],
            'avg_response_time_ms': [50.0, 100.0],
            'service_access_count': [10, 20],
            'failed_auth_attempts': [0, 1],
            'is_encrypted': [1, 0],
            'geo_location_variation': [0.1, 0.2],
            'label': ['normal', 'anomaly']
        })
        
        labeled_df = mock_df.copy()
        unlabeled_df = pd.DataFrame()
        
        self.mock_dataset_service.download_dataset.return_value = "path/to/dataset"
        self.mock_dataset_service.load_dataset.return_value = mock_df
        self.mock_dataset_service.split_dataset.return_value = (labeled_df, unlabeled_df)
        
        # Act
        with patch('builtins.print'):  # Mock print statements
            result = self.use_case.execute()
        
        # Assert
        assert result.status == "trained_from_kaggle"
        assert result.samples == 2
        assert result.file_path == "models/isoforest.joblib"
        assert result.features == 11
        
        # Verificar llamadas al servicio
        self.mock_dataset_service.download_dataset.assert_called_once()
        self.mock_dataset_service.load_dataset.assert_called_once_with("path/to/dataset")
        self.mock_dataset_service.split_dataset.assert_called_once_with(mock_df, labeled_ratio=0.2)
        self.mock_dataset_service.save_datasets.assert_called_once_with(labeled_df, unlabeled_df)
        
        # Verificar que se llamó al detector
        self.mock_detector.fit.assert_called_once()
        call_args = self.mock_detector.fit.call_args[0][0]
        assert len(call_args) == 2
        assert all(isinstance(log, LogEntry) for log in call_args)
    
    def test_execute_with_empty_labeled_dataframe(self):
        """Test ejecución con DataFrame etiquetado vacío."""
        # Arrange
        empty_df = pd.DataFrame()
        mock_df = pd.DataFrame({
            'timestamp': ['2024-01-01T00:00:00Z'],
            'device_id': ['device_001'],
            'device_type': ['thermostat'],
            'cpu_usage': [50.0],
            'memory_usage': [60.0],
            'network_in_kb': [1000],
            'network_out_kb': [500],
            'packet_rate': [100],
            'avg_response_time_ms': [50.0],
            'service_access_count': [10],
            'failed_auth_attempts': [0],
            'is_encrypted': [1],
            'geo_location_variation': [0.1],
            'label': ['normal']
        })
        
        self.mock_dataset_service.download_dataset.return_value = "path/to/dataset"
        self.mock_dataset_service.load_dataset.return_value = mock_df
        self.mock_dataset_service.split_dataset.return_value = (empty_df, mock_df)
        
        # Act
        with patch('builtins.print'):
            result = self.use_case.execute()
        
        # Assert
        assert result.status == "trained_from_kaggle"
        assert result.samples == 0
        assert result.file_path == "models/isoforest.joblib"
        assert result.features == 11
        
        # Verificar que se llamó al detector con lista vacía
        self.mock_detector.fit.assert_called_once()
        call_args = self.mock_detector.fit.call_args[0][0]
        assert len(call_args) == 0
    
    def test_execute_with_nan_labels(self):
        """Test ejecución con labels NaN."""
        # Arrange
        mock_df = pd.DataFrame({
            'timestamp': ['2024-01-01T00:00:00Z', '2024-01-01T01:00:00Z'],
            'device_id': ['device_001', 'device_002'],
            'device_type': ['thermostat', 'sensor'],
            'cpu_usage': [50.0, 75.0],
            'memory_usage': [60.0, 80.0],
            'network_in_kb': [1000, 2000],
            'network_out_kb': [500, 1000],
            'packet_rate': [100, 200],
            'avg_response_time_ms': [50.0, 100.0],
            'service_access_count': [10, 20],
            'failed_auth_attempts': [0, 1],
            'is_encrypted': [1, 0],
            'geo_location_variation': [0.1, 0.2],
            'label': ['normal', pd.NA]  # Un label válido y uno NaN
        })
        
        labeled_df = mock_df.copy()
        unlabeled_df = pd.DataFrame()
        
        self.mock_dataset_service.download_dataset.return_value = "path/to/dataset"
        self.mock_dataset_service.load_dataset.return_value = mock_df
        self.mock_dataset_service.split_dataset.return_value = (labeled_df, unlabeled_df)
        
        # Act
        with patch('builtins.print'):
            result = self.use_case.execute()
        
        # Assert
        assert result.status == "trained_from_kaggle"
        assert result.samples == 2
        
        # Verificar que se crearon LogEntry correctamente
        self.mock_detector.fit.assert_called_once()
        call_args = self.mock_detector.fit.call_args[0][0]
        assert len(call_args) == 2
        assert call_args[0].label == "normal"
        assert call_args[1].label is None  # NaN se convierte a None
    
    def test_convert_dataframe_to_log_entries(self):
        """Test conversión de DataFrame a LogEntry."""
        # Arrange
        df = pd.DataFrame({
            'timestamp': ['2024-01-01T00:00:00Z'],
            'device_id': ['device_001'],
            'device_type': ['thermostat'],
            'cpu_usage': [50.0],
            'memory_usage': [60.0],
            'network_in_kb': [1000],
            'network_out_kb': [500],
            'packet_rate': [100],
            'avg_response_time_ms': [50.0],
            'service_access_count': [10],
            'failed_auth_attempts': [0],
            'is_encrypted': [1],
            'geo_location_variation': [0.1],
            'label': ['normal']
        })
        
        # Act
        result = self.use_case._convert_dataframe_to_log_entries(df)
        
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
    
    def test_convert_dataframe_to_log_entries_with_nan_values(self):
        """Test conversión con valores NaN."""
        # Arrange
        df = pd.DataFrame({
            'timestamp': ['2024-01-01T00:00:00Z'],
            'device_id': ['device_001'],
            'device_type': ['thermostat'],
            'cpu_usage': [0.0],
            'memory_usage': [0.0],
            'network_in_kb': [0],
            'network_out_kb': [0],
            'packet_rate': [0],
            'avg_response_time_ms': [0.0],
            'service_access_count': [0],
            'failed_auth_attempts': [0],
            'is_encrypted': [0],
            'geo_location_variation': [0.0],
            'label': [pd.NA]
        })
        
        # Act
        result = self.use_case._convert_dataframe_to_log_entries(df)
        
        # Assert
        assert len(result) == 1
        assert isinstance(result[0], LogEntry)
        assert result[0].cpu_usage == 0.0
        assert result[0].memory_usage == 0.0
        assert result[0].network_in_kb == 0
        assert result[0].label is None  # pd.NA se convierte a None
    
    def test_convert_dataframe_to_log_entries_empty_dataframe(self):
        """Test conversión con DataFrame vacío."""
        # Arrange
        empty_df = pd.DataFrame()
        
        # Act
        result = self.use_case._convert_dataframe_to_log_entries(empty_df)
        
        # Assert
        assert len(result) == 0
        assert isinstance(result, list)
    
    def test_convert_dataframe_to_log_entries_with_different_data_types(self):
        """Test conversión con diferentes tipos de datos."""
        # Arrange
        df = pd.DataFrame({
            'timestamp': [1234567890],  # Timestamp como número
            'device_id': [12345],  # Device ID como número
            'device_type': ['thermostat'],
            'cpu_usage': [50],
            'memory_usage': [60],
            'network_in_kb': [1000.5],  # Float en lugar de int
            'network_out_kb': [500],
            'packet_rate': [100],
            'avg_response_time_ms': [50],
            'service_access_count': [10],
            'failed_auth_attempts': [0],
            'is_encrypted': [1],
            'geo_location_variation': [0.1],
            'label': ['normal']
        })
        
        # Act
        result = self.use_case._convert_dataframe_to_log_entries(df)
        
        # Assert
        assert len(result) == 1
        assert isinstance(result[0], LogEntry)
        assert result[0].timestamp == "1234567890"
        assert result[0].device_id == "12345"
        assert result[0].cpu_usage == 50.0
        assert result[0].memory_usage == 60.0
        assert result[0].network_in_kb == 1000  # Se convierte a int
        assert result[0].label == "normal"
