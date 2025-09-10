"""
Tests para el SupervisedThreatDetectorAdapter.

Prueba la funcionalidad del adaptador que implementa ThreatDetectorInterface
usando SupervisedThreatDetector del framework.
"""

import pytest
from unittest.mock import Mock, patch
from src.adapters.ml.supervised_threat_detector_adapter import SupervisedThreatDetectorAdapter
from src.application.interfaces.threat_detector_interface import ThreatDetectorInterface


class TestSupervisedThreatDetectorAdapter:
    """Tests para el SupervisedThreatDetectorAdapter."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.model_path = "test_models/supervised_model.joblib"
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_implements_interface(self, mock_exists, mock_detector_class):
        """Test que el adaptador implementa la interfaz correcta."""
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector.is_trained = True
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter(self.model_path)
        assert isinstance(adapter, ThreatDetectorInterface)
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_init_with_model_path(self, mock_exists, mock_detector_class):
        """Test de inicialización con ruta de modelo."""
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector.is_trained = True
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter(self.model_path)
        assert adapter.model_path == self.model_path
        assert hasattr(adapter, 'detector')
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_init_with_default_path(self, mock_exists, mock_detector_class):
        """Test de inicialización con ruta por defecto."""
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector.is_trained = True
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter()
        assert adapter.model_path == "models/supervised_model.joblib"
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_predict_success(self, mock_exists, mock_detector_class):
        """Test de predicción exitosa."""
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector.is_trained = True
        mock_detector.predict.return_value = {
            'is_attack': True,
            'confidence': 0.85,
            'probability': 0.87,
            'reasoning': 'Múltiples indicadores de ataque detectados'
        }
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter(self.model_path)
        
        # Datos de entrada
        logs = [
            {
                "session_id": "test1",
                "network_packet_size": 500,
                "protocol_type": "TCP",
                "login_attempts": 3,
                "session_duration": 300.0,
                "encryption_used": "AES",
                "ip_reputation_score": 0.2,
                "failed_logins": 3,
                "browser_type": "Chrome",
                "unusual_time_access": 0
            }
        ]
        
        # Ejecutar
        result = adapter.predict(logs)
        
        # Verificar
        assert result['is_attack'] == True
        assert result['confidence'] == 0.85
        assert result['probability'] == 0.87
        assert 'Múltiples indicadores' in result['reasoning']
        
        # Verificar que se llamó el método predict del detector
        mock_detector.predict.assert_called_once_with(logs)
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_predict_normal_behavior(self, mock_exists, mock_detector_class):
        """Test de predicción de comportamiento normal."""
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector.is_trained = True
        mock_detector.predict.return_value = {
            'is_attack': False,
            'confidence': 0.90,
            'probability': 0.15,
            'reasoning': 'Comportamiento normal detectado'
        }
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter(self.model_path)
        
        # Datos de entrada
        logs = [
            {
                "session_id": "test2",
                "network_packet_size": 400,
                "protocol_type": "UDP",
                "login_attempts": 1,
                "session_duration": 100.0,
                "encryption_used": "AES",
                "ip_reputation_score": 0.8,
                "failed_logins": 0,
                "browser_type": "Firefox",
                "unusual_time_access": 0
            }
        ]
        
        # Ejecutar
        result = adapter.predict(logs)
        
        # Verificar
        assert result['is_attack'] == False
        assert result['confidence'] == 0.90
        assert result['probability'] == 0.15
        assert 'Comportamiento normal' in result['reasoning']
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_predict_error(self, mock_exists, mock_detector_class):
        """Test de error en predicción."""
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector.is_trained = True
        mock_detector.predict.side_effect = Exception("Error en predicción del modelo")
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter(self.model_path)
        
        # Datos de entrada
        logs = [{"session_id": "test3"}]
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(Exception, match="Error en predicción del modelo"):
            adapter.predict(logs)
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_predict_empty_logs(self, mock_exists, mock_detector_class):
        """Test de predicción con logs vacíos."""
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector.is_trained = True
        mock_detector.predict.return_value = {
            'is_attack': False,
            'confidence': 0.95,
            'probability': 0.05,
            'reasoning': 'Sin datos para analizar'
        }
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter(self.model_path)
        
        # Ejecutar
        result = adapter.predict([])
        
        # Verificar
        assert result['is_attack'] == False
        assert result['confidence'] == 0.95
        assert result['probability'] == 0.05
        assert 'Sin datos' in result['reasoning']
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_predict_multiple_logs(self, mock_exists, mock_detector_class):
        """Test de predicción con múltiples logs."""
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector.is_trained = True
        mock_detector.predict.return_value = {
            'is_attack': True,
            'confidence': 0.75,
            'probability': 0.80,
            'reasoning': 'Patrón de ataque detectado en múltiples sesiones'
        }
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter(self.model_path)
        
        # Datos de entrada
        logs = [
            {"session_id": "test1", "failed_logins": 5},
            {"session_id": "test2", "failed_logins": 3},
            {"session_id": "test3", "failed_logins": 4}
        ]
        
        # Ejecutar
        result = adapter.predict(logs)
        
        # Verificar
        assert result['is_attack'] == True
        assert result['confidence'] == 0.75
        assert result['probability'] == 0.80
        assert 'múltiples sesiones' in result['reasoning']
        
        # Verificar que se llamó el método predict del detector
        mock_detector.predict.assert_called_once_with(logs)
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_is_ready_true(self, mock_exists, mock_detector_class):
        """Test de verificación cuando está listo."""
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector.is_trained = True
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter(self.model_path)
        
        # Ejecutar
        result = adapter.is_ready()
        
        # Verificar
        assert result == True
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_is_ready_false(self, mock_exists, mock_detector_class):
        """Test de verificación cuando no está listo."""
        mock_exists.return_value = False
        mock_detector = Mock()
        mock_detector.is_trained = False
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter(self.model_path)
        
        # Ejecutar
        result = adapter.is_ready()
        
        # Verificar
        assert result == False
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_predict_when_not_ready(self, mock_exists, mock_detector_class):
        """Test de predicción cuando no está listo."""
        mock_exists.return_value = False
        mock_detector = Mock()
        mock_detector.is_trained = False
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter(self.model_path)
        
        # Datos de entrada
        logs = [{"session_id": "test"}]
        
        # Ejecutar
        result = adapter.predict(logs)
        
        # Verificar que devuelve valores por defecto
        assert result['is_attack'] == False
        assert result['confidence'] == 0.0
        assert result['probability'] == 0.0
        assert 'no está listo' in result['reasoning']
    
    @patch('src.adapters.ml.supervised_threat_detector_adapter.SupervisedThreatDetector')
    @patch('os.path.exists')
    def test_predict_with_different_log_formats(self, mock_exists, mock_detector_class):
        """Test de predicción con diferentes formatos de logs."""
        mock_exists.return_value = True
        mock_detector = Mock()
        mock_detector.is_trained = True
        mock_detector.predict.return_value = {
            'is_attack': True,
            'confidence': 0.88,
            'probability': 0.92,
            'reasoning': 'Formato de log sospechoso detectado'
        }
        mock_detector_class.return_value = mock_detector
        
        adapter = SupervisedThreatDetectorAdapter(self.model_path)
        
        # Diferentes formatos de logs
        logs = [
            {"session_id": "test1", "failed_logins": 3, "ip_reputation_score": 0.1},
            {"session_id": "test2", "login_attempts": 10, "unusual_time_access": 1},
            {"session_id": "test3", "network_packet_size": 1000, "protocol_type": "ICMP"}
        ]
        
        # Ejecutar
        result = adapter.predict(logs)
        
        # Verificar
        assert result['is_attack'] == True
        assert result['confidence'] == 0.88
        assert result['probability'] == 0.92
        assert 'Formato de log' in result['reasoning']
        
        # Verificar que se llamó el método predict del detector
        mock_detector.predict.assert_called_once_with(logs)
