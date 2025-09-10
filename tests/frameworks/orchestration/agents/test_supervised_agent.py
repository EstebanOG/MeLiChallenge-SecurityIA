"""
Tests para el SupervisedAgent.

Prueba la funcionalidad del agente supervisado que detecta amenazas
usando técnicas de machine learning.
"""

import pytest
from unittest.mock import Mock, patch
from src.frameworks.orchestration.agents.supervised_agent import SupervisedAgent
from src.frameworks.orchestration.agents.base_agent import LangGraphAgentState
from src.application.interfaces.threat_detector_interface import ThreatDetectorInterface


class TestSupervisedAgent:
    """Tests para el SupervisedAgent."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        # Mock del detector de amenazas
        self.mock_detector = Mock(spec=ThreatDetectorInterface)
        self.agent = SupervisedAgent(self.mock_detector)
    
    def test_init_with_detector(self):
        """Test de inicialización con detector."""
        assert self.agent.name == "supervised_agent"
        assert self.agent.threat_detector == self.mock_detector
    
    def test_init_without_detector_raises_error(self):
        """Test de inicialización sin detector debe fallar."""
        with pytest.raises(TypeError):
            SupervisedAgent()  # Sin detector
    
    def test_execute_with_attack_detected(self):
        """Test de ejecución con ataque detectado."""
        # Configurar mock
        self.mock_detector.is_ready.return_value = True
        self.mock_detector.predict.return_value = {
            'is_attack': True,
            'confidence': 0.85,
            'probability': 0.87,
            'reasoning': 'Múltiples indicadores de ataque detectados'
        }
        
        # Estado de entrada
        logs = [{'session_id': 'test', 'failed_logins': 3}]
        state: LangGraphAgentState = {
            'logs': logs,
            'agent_results': {},
            'execution_path': []
        }
        
        # Ejecutar
        result_state = self.agent.execute(state)
        
        # Verificar
        assert 'agent_results' in result_state
        assert 'supervised_agent' in result_state['agent_results']
        
        result = result_state['agent_results']['supervised_agent']
        assert result['decision'] == 'attack_known'
        assert result['confidence'] == 0.85
        assert result['probability'] == 0.87
        assert result['threat_level'] == 'high'  # probability > 0.8
        assert result['next_agent'] == 'decision_agent'
    
    def test_execute_with_normal_behavior(self):
        """Test de ejecución con comportamiento normal."""
        # Configurar mock
        self.mock_detector.is_ready.return_value = True
        self.mock_detector.predict.return_value = {
            'is_attack': False,
            'confidence': 0.90,
            'probability': 0.15,
            'reasoning': 'Comportamiento normal detectado'
        }
        
        # Estado de entrada
        logs = [{'session_id': 'test', 'failed_logins': 1}]
        state: LangGraphAgentState = {
            'logs': logs,
            'agent_results': {},
            'execution_path': []
        }
        
        # Ejecutar
        result_state = self.agent.execute(state)
        
        # Verificar
        result = result_state['agent_results']['supervised_agent']
        assert result['decision'] == 'normal'
        assert result['confidence'] == 0.90
        assert result['probability'] == 0.15
        assert result['threat_level'] == 'low'
        assert result['next_agent'] == 'unsupervised_agent'
    
    def test_execute_with_medium_threat_level(self):
        """Test de ejecución con nivel de amenaza medio."""
        # Configurar mock
        self.mock_detector.is_ready.return_value = True
        self.mock_detector.predict.return_value = {
            'is_attack': True,
            'confidence': 0.75,
            'probability': 0.70,  # < 0.8, debe ser medium
            'reasoning': 'Ataque detectado con probabilidad media'
        }
        
        # Estado de entrada
        logs = [{'session_id': 'test', 'failed_logins': 2}]
        state: LangGraphAgentState = {
            'logs': logs,
            'agent_results': {},
            'execution_path': []
        }
        
        # Ejecutar
        result_state = self.agent.execute(state)
        
        # Verificar
        result = result_state['agent_results']['supervised_agent']
        assert result['threat_level'] == 'medium'
    
    def test_execute_detector_not_ready_raises_error(self):
        """Test de ejecución cuando el detector no está listo."""
        # Configurar mock
        self.mock_detector.is_ready.return_value = False
        
        # Estado de entrada
        logs = [{'session_id': 'test'}]
        state: LangGraphAgentState = {
            'logs': logs,
            'agent_results': {},
            'execution_path': []
        }
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(ValueError, match="El modelo ML no está entrenado"):
            self.agent.execute(state)
    
    def test_execute_detector_predict_error_raises_error(self):
        """Test de ejecución cuando el detector falla en predicción."""
        # Configurar mock
        self.mock_detector.is_ready.return_value = True
        self.mock_detector.predict.side_effect = Exception("Error en predicción")
        
        # Estado de entrada
        logs = [{'session_id': 'test'}]
        state: LangGraphAgentState = {
            'logs': logs,
            'agent_results': {},
            'execution_path': []
        }
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(Exception, match="Error en predicción"):
            self.agent.execute(state)
    
    def test_execute_empty_logs(self):
        """Test de ejecución con logs vacíos."""
        # Configurar mock
        self.mock_detector.is_ready.return_value = True
        self.mock_detector.predict.return_value = {
            'is_attack': False,
            'confidence': 0.95,
            'probability': 0.05,
            'reasoning': 'Sin logs para analizar'
        }
        
        # Estado de entrada con logs vacíos
        state: LangGraphAgentState = {
            'logs': [],
            'agent_results': {},
            'execution_path': []
        }
        
        # Ejecutar
        result_state = self.agent.execute(state)
        
        # Verificar
        result = result_state['agent_results']['supervised_agent']
        assert result['decision'] == 'normal'
    
    def test_execute_multiple_logs(self):
        """Test de ejecución con múltiples logs."""
        # Configurar mock
        self.mock_detector.is_ready.return_value = True
        self.mock_detector.predict.return_value = {
            'is_attack': True,
            'confidence': 0.88,
            'probability': 0.92,
            'reasoning': 'Múltiples logs con indicadores de ataque'
        }
        
        # Estado de entrada con múltiples logs
        logs = [
            {'session_id': 'test1', 'failed_logins': 3},
            {'session_id': 'test2', 'failed_logins': 2},
            {'session_id': 'test3', 'failed_logins': 4}
        ]
        state: LangGraphAgentState = {
            'logs': logs,
            'agent_results': {},
            'execution_path': []
        }
        
        # Ejecutar
        result_state = self.agent.execute(state)
        
        # Verificar que se llamó predict con todos los logs
        self.mock_detector.predict.assert_called_once_with(logs)
        
        # Verificar resultado
        result = result_state['agent_results']['supervised_agent']
        assert result['decision'] == 'attack_known'
        assert result['threat_level'] == 'high'
