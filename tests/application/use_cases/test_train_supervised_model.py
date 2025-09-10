"""
Tests para el TrainSupervisedModelUseCase.

Prueba la funcionalidad del caso de uso que maneja el entrenamiento
del modelo supervisado de detección de amenazas.
"""

import pytest
from unittest.mock import Mock, patch
from src.application.use_cases.train_supervised_model import TrainSupervisedModelUseCase
from src.application.interfaces.supervised_model_interface import SupervisedModelInterface
from src.domain.entities.dto import SupervisedTrainResponseDTO


class TestTrainSupervisedModelUseCase:
    """Tests para el TrainSupervisedModelUseCase."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.mock_supervised_model = Mock(spec=SupervisedModelInterface)
        self.use_case = TrainSupervisedModelUseCase(self.mock_supervised_model)
    
    def test_init(self):
        """Test de inicialización."""
        assert self.use_case.supervised_model == self.mock_supervised_model
        assert self.use_case.model_path == "models/supervised_model.joblib"
    
    @patch('os.path.exists')
    def test_execute_success(self, mock_exists):
        """Test de ejecución exitosa del entrenamiento."""
        # Configurar mocks
        mock_exists.return_value = True
        mock_metrics = {
            'auc_score': 0.8789,
            'precision': 0.8234,
            'recall': 0.8012,
            'f1_score': 0.8121,
            'train_samples': 7629,
            'test_samples': 1908,
            'training_time': 15.5
        }
        self.mock_supervised_model.train.return_value = mock_metrics
        self.mock_supervised_model.get_feature_importance.return_value = {
            'failed_logins': 0.25,
            'login_attempts': 0.20,
            'ip_reputation_score': 0.15
        }
        
        # Ejecutar
        result = self.use_case.execute()
        
        # Verificar
        assert isinstance(result, SupervisedTrainResponseDTO)
        assert result.success == True
        assert "Modelo supervisado entrenado exitosamente" in result.message
        assert result.model_path == "models/supervised_model.joblib"
        assert result.training_time == 15.5
        assert result.metrics['auc_score'] == 0.8789
        assert result.metrics['precision'] == 0.8234
        assert result.metrics['recall'] == 0.8012
        assert result.metrics['f1_score'] == 0.8121
        
        # Verificar que se llamaron los métodos
        self.mock_supervised_model.train.assert_called_once()
        self.mock_supervised_model.get_feature_importance.assert_called_once()
    
    @patch('os.path.exists')
    def test_execute_dataset_not_found(self, mock_exists):
        """Test de error cuando el dataset no existe."""
        # Configurar mock
        mock_exists.return_value = False  # Dataset no existe
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(FileNotFoundError, match="Dataset no encontrado"):
            self.use_case.execute()
    
    @patch('os.path.exists')
    def test_execute_training_error(self, mock_exists):
        """Test de error durante el entrenamiento."""
        # Configurar mocks
        mock_exists.return_value = True
        self.mock_supervised_model.train.side_effect = Exception("Error en entrenamiento")
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(Exception, match="Error en entrenamiento"):
            self.use_case.execute()
    
    @patch('os.path.exists')
    def test_execute_feature_importance_error(self, mock_exists):
        """Test de error al obtener importancia de características."""
        # Configurar mocks
        mock_exists.return_value = True
        mock_metrics = {
            'auc_score': 0.8789,
            'precision': 0.8234,
            'recall': 0.8012,
            'f1_score': 0.8121,
            'train_samples': 7629,
            'test_samples': 1908,
            'training_time': 15.5
        }
        self.mock_supervised_model.train.return_value = mock_metrics
        self.mock_supervised_model.get_feature_importance.side_effect = Exception("Error al obtener importancia")
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(Exception, match="Error al obtener importancia"):
            self.use_case.execute()
    
    def test_is_model_trained_true(self):
        """Test de verificación cuando el modelo está entrenado."""
        # Configurar mock
        self.mock_supervised_model.is_trained.return_value = True
        
        # Ejecutar
        result = self.use_case.is_model_trained()
        
        # Verificar
        assert result == True
        self.mock_supervised_model.is_trained.assert_called_once()
    
    def test_is_model_trained_false(self):
        """Test de verificación cuando el modelo no está entrenado."""
        # Configurar mock
        self.mock_supervised_model.is_trained.return_value = False
        
        # Ejecutar
        result = self.use_case.is_model_trained()
        
        # Verificar
        assert result == False
        self.mock_supervised_model.is_trained.assert_called_once()
    
    @patch('os.path.exists')
    def test_get_model_status_with_metrics_file(self, mock_exists):
        """Test de obtención de estado con archivo de métricas."""
        # Configurar mocks
        mock_exists.return_value = True
        self.mock_supervised_model.is_trained.return_value = True
        
        # Mock del archivo de métricas
        mock_metrics = {
            "auc_score": 0.8789,
            "precision": 0.8234,
            "recall": 0.8012,
            "f1_score": 0.8121
        }
        
        with patch('builtins.open', create=True) as mock_open:
            with patch('json.load') as mock_json_load:
                mock_json_load.return_value = mock_metrics
                mock_open.return_value.__enter__.return_value = mock_open.return_value
                
                # Ejecutar
                result = self.use_case.get_model_status()
        
        # Verificar
        assert result["is_trained"] == True
        assert result["model_path"] == "models/supervised_model.joblib"
        assert result["model_exists"] == True
        assert result["metrics"]["auc_score"] == 0.8789
        assert result["metrics"]["precision"] == 0.8234
        assert result["metrics"]["recall"] == 0.8012
        assert result["metrics"]["f1_score"] == 0.8121
    
    @patch('os.path.exists')
    def test_get_model_status_without_metrics_file(self, mock_exists):
        """Test de obtención de estado sin archivo de métricas."""
        # Configurar mocks
        mock_exists.side_effect = lambda path: path != "models/supervised_model_metrics.json"
        self.mock_supervised_model.is_trained.return_value = True
        
        # Ejecutar
        result = self.use_case.get_model_status()
        
        # Verificar
        assert result["is_trained"] == True
        assert result["model_path"] == "models/supervised_model.joblib"
        assert result["model_exists"] == True
        assert result["metrics"]["auc_score"] == "N/A - Métricas no guardadas"
        assert result["metrics"]["precision"] == "N/A - Métricas no guardadas"
        assert result["metrics"]["recall"] == "N/A - Métricas no guardadas"
        assert result["metrics"]["f1_score"] == "N/A - Métricas no guardadas"
    
    @patch('os.path.exists')
    def test_get_model_status_metrics_file_error(self, mock_exists):
        """Test de error al cargar archivo de métricas."""
        # Configurar mocks
        mock_exists.return_value = True
        self.mock_supervised_model.is_trained.return_value = False
        
        # Ejecutar
        result = self.use_case.get_model_status()
        
        # Verificar
        assert result["is_trained"] == False
        assert result["model_path"] == "models/supervised_model.joblib"
        assert result["model_exists"] == True
        assert result["metrics"]["auc_score"] == "N/A - Modelo no entrenado"
        assert result["metrics"]["precision"] == "N/A - Modelo no entrenado"
        assert result["metrics"]["recall"] == "N/A - Modelo no entrenado"
        assert result["metrics"]["f1_score"] == "N/A - Modelo no entrenado"
    
    @patch('os.path.exists')
    def test_get_model_status_model_not_trained(self, mock_exists):
        """Test de estado cuando el modelo no está entrenado."""
        # Configurar mocks
        self.mock_supervised_model.is_trained.return_value = False
        mock_exists.return_value = False  # El archivo del modelo no existe
        
        # Ejecutar
        result = self.use_case.get_model_status()
        
        # Verificar
        assert result["is_trained"] == False
        assert result["model_path"] == "models/supervised_model.joblib"
        assert result["model_exists"] == False
        assert result["metrics"]["auc_score"] == "N/A - Modelo no entrenado"
        assert result["metrics"]["precision"] == "N/A - Modelo no entrenado"
        assert result["metrics"]["recall"] == "N/A - Modelo no entrenado"
        assert result["metrics"]["f1_score"] == "N/A - Modelo no entrenado"
    
    @patch('os.path.exists')
    def test_get_model_status_with_custom_path(self, mock_exists):
        """Test de estado con ruta de modelo personalizada."""
        # Crear caso de uso con ruta personalizada
        custom_path = "custom/models/test_model.joblib"
        use_case = TrainSupervisedModelUseCase(self.mock_supervised_model, custom_path)
        
        # Configurar mocks
        self.mock_supervised_model.is_trained.return_value = True
        # El archivo del modelo existe, pero no hay archivo de métricas
        mock_exists.side_effect = lambda path: path == custom_path
        
        # Ejecutar
        result = use_case.get_model_status()
        
        # Verificar
        assert result["is_trained"] == True
        assert result["model_path"] == custom_path
        assert result["model_exists"] == True  # El archivo del modelo existe
        assert result["metrics"]["auc_score"] == "N/A - Métricas no guardadas"
