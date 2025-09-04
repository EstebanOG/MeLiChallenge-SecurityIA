"""
Tests para el caso de uso GetDatasetSampleUseCase.

Estos tests verifican la lógica de negocio para obtener muestras del dataset.
"""

import pytest
import pandas as pd
from unittest.mock import patch, mock_open
from src.application.use_cases.get_dataset_sample import GetDatasetSampleUseCase
from src.domain.entities.dto import DatasetSampleDTO


class TestGetDatasetSampleUseCase:
    """Tests para GetDatasetSampleUseCase."""
    
    def setup_method(self):
        """Setup para cada test."""
        self.use_case = GetDatasetSampleUseCase()
    
    def test_execute_success_default_size(self):
        """Test ejecución exitosa con tamaño por defecto."""
        # Arrange
        mock_df = pd.DataFrame({
            'device_id': ['device_001', 'device_002', 'device_003', 'device_004', 'device_005'],
            'cpu_usage': [50.0, 75.0, 25.0, 90.0, 60.0],
            'memory_usage': [60.0, 80.0, 40.0, 95.0, 70.0],
            'label': ['normal', 'anomaly', 'normal', 'anomaly', 'normal']
        })
        
        with patch("pandas.read_csv", return_value=mock_df):
            with patch("pathlib.Path.exists", return_value=True):
                # Act
                result = self.use_case.execute()
        
        # Assert
        assert isinstance(result, DatasetSampleDTO)
        assert result.sample_size == 5  # Tamaño por defecto es 10, pero solo hay 5 filas
        assert result.total_rows == 5
        assert len(result.data) == 5
        assert all(isinstance(item, dict) for item in result.data)
    
    def test_execute_success_custom_size(self):
        """Test ejecución exitosa con tamaño personalizado."""
        # Arrange
        mock_df = pd.DataFrame({
            'device_id': [f'device_{i:03d}' for i in range(50)],
            'cpu_usage': [i * 2.0 for i in range(50)],
            'memory_usage': [i * 1.5 for i in range(50)],
            'label': ['normal' if i % 2 == 0 else 'anomaly' for i in range(50)]
        })
        
        with patch("pandas.read_csv", return_value=mock_df):
            with patch("pathlib.Path.exists", return_value=True):
                # Act
                result = self.use_case.execute(size=10)
        
        # Assert
        assert isinstance(result, DatasetSampleDTO)
        assert result.sample_size == 10
        assert result.total_rows == 50
        assert len(result.data) == 10
        assert all(isinstance(item, dict) for item in result.data)
    
    def test_execute_size_limit_enforcement(self):
        """Test que se respeta el límite máximo de tamaño."""
        # Arrange
        mock_df = pd.DataFrame({
            'device_id': [f'device_{i:03d}' for i in range(200)],
            'cpu_usage': [i * 2.0 for i in range(200)],
            'memory_usage': [i * 1.5 for i in range(200)],
            'label': ['normal' if i % 2 == 0 else 'anomaly' for i in range(200)]
        })
        
        with patch("pandas.read_csv", return_value=mock_df):
            with patch("pathlib.Path.exists", return_value=True):
                # Act
                result = self.use_case.execute(size=150)  # Mayor al límite de 100
        
        # Assert
        assert isinstance(result, DatasetSampleDTO)
        assert result.sample_size == 100  # Limitado a 100
        assert result.total_rows == 200
        assert len(result.data) == 100
    
    def test_execute_file_not_found(self):
        """Test ejecución cuando el archivo no existe."""
        # Arrange
        with patch("pathlib.Path.exists", return_value=False):
            # Act & Assert
            with pytest.raises(FileNotFoundError) as exc_info:
                self.use_case.execute()
            
            assert "Dataset no encontrado" in str(exc_info.value)
            assert "Ejecuta /train/iot/kaggle primero" in str(exc_info.value)
    
    def test_execute_with_empty_dataframe(self):
        """Test ejecución con DataFrame vacío."""
        # Arrange
        empty_df = pd.DataFrame()
        
        with patch("pandas.read_csv", return_value=empty_df):
            with patch("pathlib.Path.exists", return_value=True):
                # Act
                result = self.use_case.execute()
        
        # Assert
        assert isinstance(result, DatasetSampleDTO)
        assert result.sample_size == 0
        assert result.total_rows == 0
        assert len(result.data) == 0
    
    def test_execute_with_single_row(self):
        """Test ejecución con DataFrame de una sola fila."""
        # Arrange
        single_row_df = pd.DataFrame({
            'device_id': ['device_001'],
            'cpu_usage': [50.0],
            'memory_usage': [60.0],
            'label': ['normal']
        })
        
        with patch("pandas.read_csv", return_value=single_row_df):
            with patch("pathlib.Path.exists", return_value=True):
                # Act
                result = self.use_case.execute(size=5)
        
        # Assert
        assert isinstance(result, DatasetSampleDTO)
        assert result.sample_size == 1
        assert result.total_rows == 1
        assert len(result.data) == 1
        assert result.data[0]['device_id'] == 'device_001'
    
    def test_execute_with_different_data_types(self):
        """Test ejecución con diferentes tipos de datos en el DataFrame."""
        # Arrange
        mixed_df = pd.DataFrame({
            'device_id': ['device_001', 'device_002'],
            'cpu_usage': [50.0, 75.5],
            'memory_usage': [60, 80],  # Int en lugar de float
            'network_in_kb': [1000, 2000],
            'is_encrypted': [True, False],  # Boolean
            'label': ['normal', None],  # Con None
            'timestamp': [pd.Timestamp('2024-01-01'), pd.Timestamp('2024-01-02')]
        })
        
        with patch("pandas.read_csv", return_value=mixed_df):
            with patch("pathlib.Path.exists", return_value=True):
                # Act
                result = self.use_case.execute()
        
        # Assert
        assert isinstance(result, DatasetSampleDTO)
        assert result.sample_size == 2
        assert result.total_rows == 2
        assert len(result.data) == 2
        
        # Verificar que los datos se convierten correctamente a dict
        data = result.data[0]
        assert data['device_id'] == 'device_001'
        assert data['cpu_usage'] == 50.0
        assert data['memory_usage'] == 60
        assert data['network_in_kb'] == 1000
        assert data['is_encrypted'] is True
        assert data['label'] == 'normal'
    
    def test_execute_with_nan_values(self):
        """Test ejecución con valores NaN en el DataFrame."""
        # Arrange
        nan_df = pd.DataFrame({
            'device_id': ['device_001', 'device_002'],
            'cpu_usage': [50.0, pd.NA],
            'memory_usage': [pd.NA, 80.0],
            'label': ['normal', 'anomaly']
        })
        
        with patch("pandas.read_csv", return_value=nan_df):
            with patch("pathlib.Path.exists", return_value=True):
                # Act
                result = self.use_case.execute()
        
        # Assert
        assert isinstance(result, DatasetSampleDTO)
        assert result.sample_size == 2
        assert result.total_rows == 2
        assert len(result.data) == 2
        
        # Verificar que los NaN se manejan correctamente
        data = result.data[0]
        assert data['cpu_usage'] == 50.0
        assert pd.isna(data['memory_usage'])
        
        data = result.data[1]
        assert pd.isna(data['cpu_usage'])
        assert data['memory_usage'] == 80.0
    
    def test_execute_random_state_consistency(self):
        """Test que el random_state produce resultados consistentes."""
        # Arrange
        mock_df = pd.DataFrame({
            'device_id': [f'device_{i:03d}' for i in range(20)],
            'cpu_usage': [i * 2.0 for i in range(20)],
            'memory_usage': [i * 1.5 for i in range(20)],
            'label': ['normal' if i % 2 == 0 else 'anomaly' for i in range(20)]
        })
        
        with patch("pandas.read_csv", return_value=mock_df):
            with patch("pathlib.Path.exists", return_value=True):
                # Act - Ejecutar dos veces con el mismo tamaño
                result1 = self.use_case.execute(size=5)
                result2 = self.use_case.execute(size=5)
        
        # Assert - Los resultados deben ser idénticos debido al random_state fijo
        assert isinstance(result1, DatasetSampleDTO)
        assert isinstance(result2, DatasetSampleDTO)
        assert result1.sample_size == result2.sample_size == 5
        assert result1.total_rows == result2.total_rows == 20
        assert len(result1.data) == len(result2.data) == 5
        
        # Los datos deben ser los mismos (mismo random_state)
        assert result1.data == result2.data
