"""
Tests para el SupervisedModelAdapter.

Prueba la funcionalidad del adaptador que implementa SupervisedModelInterface
usando SupervisedThreatDetector del framework.
"""

import pytest
from unittest.mock import Mock, patch, mock_open
import os
import json
from src.adapters.ml.supervised_model_adapter import SupervisedModelAdapter
from src.application.interfaces.supervised_model_interface import SupervisedModelInterface


class TestSupervisedModelAdapter:
    """Tests para el SupervisedModelAdapter."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.model_path = "test_models/supervised_model.joblib"
        self.adapter = SupervisedModelAdapter(self.model_path)
    
    def test_implements_interface(self):
        """Test que el adaptador implementa la interfaz correcta."""
        assert isinstance(self.adapter, SupervisedModelInterface)
    
    def test_init_with_model_path(self):
        """Test de inicialización con ruta de modelo."""
        assert self.adapter.model_path == self.model_path
        assert hasattr(self.adapter, 'detector')
        assert self.adapter._is_trained == False
    
    def test_init_with_default_path(self):
        """Test de inicialización con ruta por defecto."""
        adapter = SupervisedModelAdapter()
        assert adapter.model_path == "models/supervised_model.joblib"
    
    @patch('src.adapters.ml.supervised_model_adapter.SupervisedThreatDetector')
    def test_train_success(self, mock_detector_class):
        """Test de entrenamiento exitoso."""
        # Configurar mock
        mock_detector = Mock()
        mock_detector.train.return_value = {
            'auc_score': 0.85,
            'precision': 0.82,
            'recall': 0.80,
            'f1_score': 0.81,
            'train_samples': 1000,
            'test_samples': 200
        }
        mock_detector_class.return_value = mock_detector
        self.adapter.detector = mock_detector
        
        # Ejecutar entrenamiento
        result = self.adapter.train("test_dataset.csv")
        
        # Verificar
        assert result['auc_score'] == 0.85
        assert result['precision'] == 0.82
        assert result['recall'] == 0.80
        assert result['f1_score'] == 0.81
        assert self.adapter._is_trained == True
        mock_detector.train.assert_called_once_with("test_dataset.csv")
    
    @patch('src.adapters.ml.supervised_model_adapter.SupervisedThreatDetector')
    def test_train_error(self, mock_detector_class):
        """Test de error en entrenamiento."""
        # Configurar mock para lanzar error
        mock_detector = Mock()
        mock_detector.train.side_effect = Exception("Error en entrenamiento")
        mock_detector_class.return_value = mock_detector
        self.adapter.detector = mock_detector
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(Exception, match="Error en entrenamiento"):
            self.adapter.train("test_dataset.csv")
        
        # Verificar que _is_trained sigue siendo False
        assert self.adapter._is_trained == False
    
    def test_is_trained_true_when_internal_flag_true(self):
        """Test de is_trained cuando la bandera interna es True."""
        self.adapter._is_trained = True
        assert self.adapter.is_trained() == True
    
    @patch('os.path.exists')
    @patch('src.adapters.ml.supervised_model_adapter.SupervisedThreatDetector')
    def test_is_trained_true_when_model_exists(self, mock_detector_class, mock_exists):
        """Test de is_trained cuando el modelo existe en disco."""
        # Configurar mocks
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector.is_trained = True
        mock_detector_class.return_value = mock_detector
        self.adapter.detector = mock_detector
        self.adapter._is_trained = False
        
        # Ejecutar
        result = self.adapter.is_trained()
        
        # Verificar
        assert result == True
        assert self.adapter._is_trained == True
        mock_detector._load_model.assert_called_once()
    
    @patch('os.path.exists')
    def test_is_trained_false_when_model_not_exists(self, mock_exists):
        """Test de is_trained cuando el modelo no existe en disco."""
        # Configurar mock
        mock_exists.return_value = False
        self.adapter._is_trained = False
        
        # Ejecutar
        result = self.adapter.is_trained()
        
        # Verificar
        assert result == False
    
    @patch('os.path.exists')
    @patch('src.adapters.ml.supervised_model_adapter.SupervisedThreatDetector')
    def test_is_trained_false_when_load_error(self, mock_detector_class, mock_exists):
        """Test de is_trained cuando hay error al cargar el modelo."""
        # Configurar mocks
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector._load_model.side_effect = Exception("Error al cargar")
        mock_detector_class.return_value = mock_detector
        self.adapter.detector = mock_detector
        self.adapter._is_trained = False
        
        # Ejecutar
        result = self.adapter.is_trained()
        
        # Verificar
        assert result == False
    
    @patch('src.adapters.ml.supervised_model_adapter.SupervisedThreatDetector')
    def test_predict_success(self, mock_detector_class):
        """Test de predicción exitosa."""
        # Configurar mock
        mock_detector = Mock()
        mock_detector.predict.return_value = {
            'is_attack': True,
            'confidence': 0.85,
            'probability': 0.87,
            'reasoning': 'Ataque detectado'
        }
        mock_detector_class.return_value = mock_detector
        self.adapter.detector = mock_detector
        
        # Datos de entrada
        logs = [{'session_id': 'test', 'failed_logins': 3}]
        
        # Ejecutar predicción
        result = self.adapter.predict(logs)
        
        # Verificar
        assert result['is_attack'] == True
        assert result['confidence'] == 0.85
        assert result['probability'] == 0.87
        assert result['reasoning'] == 'Ataque detectado'
        mock_detector.predict.assert_called_once_with(logs)
    
    @patch('src.adapters.ml.supervised_model_adapter.SupervisedThreatDetector')
    def test_predict_error(self, mock_detector_class):
        """Test de error en predicción."""
        # Configurar mock para lanzar error
        mock_detector = Mock()
        mock_detector.predict.side_effect = Exception("Error en predicción")
        mock_detector_class.return_value = mock_detector
        self.adapter.detector = mock_detector
        
        # Datos de entrada
        logs = [{'session_id': 'test'}]
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(Exception, match="Error en predicción"):
            self.adapter.predict(logs)
    
    @patch('src.adapters.ml.supervised_model_adapter.SupervisedThreatDetector')
    def test_get_feature_importance(self, mock_detector_class):
        """Test de obtención de importancia de características."""
        # Configurar mock
        mock_detector = Mock()
        mock_detector.get_feature_importance.return_value = {
            'failed_logins': 0.25,
            'ip_reputation_score': 0.20,
            'login_attempts': 0.15
        }
        mock_detector_class.return_value = mock_detector
        self.adapter.detector = mock_detector
        
        # Ejecutar
        result = self.adapter.get_feature_importance()
        
        # Verificar
        assert result['failed_logins'] == 0.25
        assert result['ip_reputation_score'] == 0.20
        assert result['login_attempts'] == 0.15
        mock_detector.get_feature_importance.assert_called_once()
    
    @patch('src.adapters.ml.supervised_model_adapter.SupervisedThreatDetector')
    def test_get_feature_importance_error(self, mock_detector_class):
        """Test de error en obtención de importancia de características."""
        # Configurar mock para lanzar error
        mock_detector = Mock()
        mock_detector.get_feature_importance.side_effect = Exception("Error al obtener importancia")
        mock_detector_class.return_value = mock_detector
        self.adapter.detector = mock_detector
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(Exception, match="Error al obtener importancia"):
            self.adapter.get_feature_importance()
    
    def test_model_path_property(self):
        """Test de la propiedad model_path."""
        assert self.adapter.model_path == self.model_path
        
        # Cambiar ruta
        new_path = "new_models/test.joblib"
        self.adapter.model_path = new_path
        assert self.adapter.model_path == new_path
