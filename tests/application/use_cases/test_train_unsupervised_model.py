"""
Tests para el TrainUnsupervisedModelUseCase.

Prueba la funcionalidad del caso de uso que maneja el entrenamiento
del modelo no supervisado de detección de anomalías.
"""

import pytest
from unittest.mock import Mock, patch
from src.application.use_cases.train_unsupervised_model import TrainUnsupervisedModelUseCase
from src.application.interfaces.anomaly_detector import AnomalyDetector
from src.domain.entities.dto import UnsupervisedTrainResponseDTO


class TestTrainUnsupervisedModelUseCase:
    """Tests para el TrainUnsupervisedModelUseCase."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.mock_anomaly_detector = Mock(spec=AnomalyDetector)
        self.use_case = TrainUnsupervisedModelUseCase(self.mock_anomaly_detector)
    
    def test_init(self):
        """Test de inicialización."""
        assert self.use_case.anomaly_detector == self.mock_anomaly_detector
        assert self.use_case.model_path == "models/isoforest.joblib"
    
    @patch('os.path.exists')
    def test_execute_success(self, mock_exists):
        """Test de ejecución exitosa del entrenamiento."""
        # Configurar mocks
        mock_exists.return_value = True
        mock_metrics = {
            'contamination': 0.2,
            'n_estimators': 200,
            'train_samples': 9520,
            'threshold': 0.5,
            'model_ready': True,
            'training_time': 8.3,
            'auc_score': 0.85,
            'precision': 0.78,
            'recall': 0.82,
            'f1_score': 0.80,
            'accuracy': 0.88
        }
        self.mock_anomaly_detector.fit_from_dataset.return_value = mock_metrics
        
        # Ejecutar
        result = self.use_case.execute()
        
        # Verificar
        assert isinstance(result, UnsupervisedTrainResponseDTO)
        assert result.success is True
        assert "Modelo no supervisado entrenado exitosamente" in result.message
        assert "Muestras: 9520" in result.message
        assert "Contaminación: 0.20" in result.message
        assert "Estimadores: 200" in result.message
        assert "AUC: 0.8500" in result.message
        assert "Precisión: 0.7800" in result.message
        assert "Recall: 0.8200" in result.message
        assert "F1: 0.8000" in result.message
        assert result.model_path == "models/isoforest.joblib"
        assert result.training_time == 8.3
        assert result.metrics['contamination'] == 0.2
        assert result.metrics['n_estimators'] == 200
        assert result.metrics['train_samples'] == 9520
        assert result.metrics['anomaly_threshold'] == 0.5
        assert result.metrics['model_ready'] == True
        assert result.metrics['features_used'] == 9
        assert result.metrics['algorithm'] == "Isolation Forest"
        assert result.metrics['contamination_rate'] == "20.0%"
        assert result.metrics['auc_score'] == 0.85
        assert result.metrics['precision'] == 0.78
        assert result.metrics['recall'] == 0.82
        assert result.metrics['f1_score'] == 0.80
        assert result.metrics['accuracy'] == 0.88
        
        # Verificar que se llamó al detector
        self.mock_anomaly_detector.fit_from_dataset.assert_called_once_with(
            "notebooks/data/processed/dataset_complete.csv"
        )
    
    @patch('os.path.exists')
    def test_execute_dataset_not_found(self, mock_exists):
        """Test cuando el dataset no existe."""
        # Configurar mocks
        mock_exists.return_value = False
        
        # Ejecutar y verificar excepción
        with pytest.raises(FileNotFoundError) as exc_info:
            self.use_case.execute()
        
        assert "Dataset no encontrado" in str(exc_info.value)
        self.mock_anomaly_detector.fit_from_dataset.assert_not_called()
    
    @patch('os.path.exists')
    def test_execute_training_error(self, mock_exists):
        """Test cuando ocurre un error durante el entrenamiento."""
        # Configurar mocks
        mock_exists.return_value = True
        self.mock_anomaly_detector.fit_from_dataset.side_effect = Exception("Error de entrenamiento")
        
        # Ejecutar y verificar excepción
        with pytest.raises(Exception) as exc_info:
            self.use_case.execute()
        
        assert "Error durante el entrenamiento: Error de entrenamiento" in str(exc_info.value)
    
    @patch('os.path.exists')
    def test_is_model_trained_true(self, mock_exists):
        """Test cuando el modelo está entrenado."""
        # Configurar mocks
        mock_exists.return_value = True
        self.mock_anomaly_detector.is_ready.return_value = True
        
        # Ejecutar
        result = self.use_case.is_model_trained()
        
        # Verificar
        assert result is True
        self.mock_anomaly_detector.is_ready.assert_called_once()
    
    @patch('os.path.exists')
    def test_is_model_trained_false_no_file(self, mock_exists):
        """Test cuando el archivo del modelo no existe."""
        # Configurar mocks
        mock_exists.return_value = False
        
        # Ejecutar
        result = self.use_case.is_model_trained()
        
        # Verificar
        assert result is False
        self.mock_anomaly_detector.is_ready.assert_not_called()
    
    @patch('os.path.exists')
    def test_is_model_trained_false_not_ready(self, mock_exists):
        """Test cuando el archivo existe pero el modelo no está listo."""
        # Configurar mocks
        mock_exists.return_value = True
        self.mock_anomaly_detector.is_ready.return_value = False
        
        # Ejecutar
        result = self.use_case.is_model_trained()
        
        # Verificar
        assert result is False
        self.mock_anomaly_detector.is_ready.assert_called_once()
    
    @patch('os.path.exists')
    def test_is_model_trained_exception(self, mock_exists):
        """Test cuando ocurre una excepción."""
        # Configurar mocks
        mock_exists.return_value = True
        self.mock_anomaly_detector.is_ready.side_effect = Exception("Error")
        
        # Ejecutar
        result = self.use_case.is_model_trained()
        
        # Verificar
        assert result is False
    
    @patch('os.path.exists')
    def test_get_model_status_trained_with_metrics(self, mock_exists):
        """Test del estado del modelo cuando está entrenado con métricas."""
        # Configurar mocks
        mock_exists.return_value = True
        self.mock_anomaly_detector.is_ready.return_value = True
        
        # Mock del archivo de métricas
        mock_metrics = {
            'contamination': 0.2,
            'n_estimators': 200,
            'train_samples': 9520,
            'threshold': 0.5
        }
        
        with patch('builtins.open', mock_open_file_with_metrics(mock_metrics)):
            with patch('json.load', return_value=mock_metrics):
                # Ejecutar
                result = self.use_case.get_model_status()
        
        # Verificar
        assert result['is_trained'] is True
        assert result['model_path'] == "models/isoforest.joblib"
        assert result['model_exists'] is True
        assert result['metrics']['train_samples'] == 9520
        assert result['metrics']['algorithm'] == "Isolation Forest"
        assert result['metrics']['features_used'] == 9
        assert result['metrics']['contamination_rate'] == "20.0%"
    
    @patch('os.path.exists')
    def test_get_model_status_trained_without_metrics(self, mock_exists):
        """Test del estado del modelo cuando está entrenado sin métricas."""
        # Configurar mocks
        mock_exists.return_value = True
        self.mock_anomaly_detector.is_ready.return_value = True
        
        # Mock de archivo de métricas que no existe
        def mock_exists_side_effect(path):
            if path == "models/isoforest.joblib":
                return True
            elif path == "models/isoforest_stats.json":
                return False
            return False
        
        mock_exists.side_effect = mock_exists_side_effect
        
        # Ejecutar
        result = self.use_case.get_model_status()
        
        # Verificar
        assert result['is_trained'] is True
        assert result['model_path'] == "models/isoforest.joblib"
        assert result['model_exists'] is True
        assert 'N/A - Métricas no guardadas' in result['metrics']['contamination']
        assert 'Re-entrena para obtener métricas completas' in result['metrics']['note']
    
    @patch('os.path.exists')
    def test_get_model_status_not_trained(self, mock_exists):
        """Test del estado del modelo cuando no está entrenado."""
        # Configurar mocks
        mock_exists.return_value = False
        self.mock_anomaly_detector.is_ready.return_value = False
        
        # Ejecutar
        result = self.use_case.get_model_status()
        
        # Verificar
        assert result['is_trained'] is False
        assert result['model_path'] == "models/isoforest.joblib"
        assert result['model_exists'] is False
        assert 'N/A - Modelo no entrenado' in result['metrics']['contamination']


def mock_open_file_with_metrics(metrics):
    """Helper para mockear archivos con métricas."""
    def mock_open(path, mode='r'):
        if 'stats.json' in path:
            return Mock()
        else:
            raise FileNotFoundError()
    return mock_open
