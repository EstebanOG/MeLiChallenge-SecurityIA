"""
Tests para el DecisionAgent.

Prueba la funcionalidad del agente de decisión que toma decisiones
de respuesta basadas en los resultados de los agentes de detección.
"""

import pytest
from unittest.mock import Mock, patch
from src.frameworks.orchestration.agents.decision_agent import DecisionAgent
from src.frameworks.orchestration.agents.base_agent import LangGraphAgentState


class TestDecisionAgent:
    """Tests para el DecisionAgent."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.agent = DecisionAgent(use_llm=False)  # Sin LLM para tests unitarios
    
    def test_init_without_llm(self):
        """Test de inicialización sin LLM."""
        agent = DecisionAgent(use_llm=False)
        assert agent.name == "decision_agent"
        assert agent.use_llm == False
        assert agent.gemini_agent is None
    
    def test_init_with_llm_but_gemini_unavailable(self):
        """Test de inicialización con LLM pero Gemini no disponible."""
        with patch('src.frameworks.orchestration.agents.decision_agent.GEMINI_AVAILABLE', False):
            agent = DecisionAgent(use_llm=True)
            assert agent.name == "decision_agent"
            assert agent.use_llm == False
            assert agent.gemini_agent is None
    
    def test_execute_no_threats_no_anomalies(self):
        """Test de ejecución sin amenazas ni anomalías."""
        # Estado con comportamiento normal
        state: LangGraphAgentState = {
            'logs': [{'session_id': 'test', 'failed_logins': 0}],
            'agent_results': {
                'supervised_agent': {
                    'decision': 'normal',
                    'threat_level': 'low',
                    'confidence': 0.9
                },
                'unsupervised_agent': {
                    'anomaly_score': 0.2,
                    'is_anomalous': False
                }
            },
            'execution_path': []
        }
        
        result_state = self.agent.execute(state)
        
        # Verificar resultado
        assert 'agent_results' in result_state
        assert 'decision_agent' in result_state['agent_results']
        
        result = result_state['agent_results']['decision_agent']
        assert result['decision'] == 'action_taken'
        assert result['action'] == 'monitor'
        assert result['confidence'] == 0.9
        assert result['next_agent'] == 'report_agent'
    
    def test_execute_attack_known_brute_force(self):
        """Test de ejecución con ataque conocido de fuerza bruta."""
        # Estado con ataque de fuerza bruta
        state: LangGraphAgentState = {
            'logs': [{'session_id': 'test', 'failed_logins': 5, 'login_attempts': 8}],
            'agent_results': {
                'supervised_agent': {
                    'decision': 'attack_known',
                    'threat_level': 'high',
                    'confidence': 0.85
                },
                'unsupervised_agent': {
                    'anomaly_score': 0.3,
                    'is_anomalous': False
                }
            },
            'execution_path': []
        }
        
        result_state = self.agent.execute(state)
        
        result = result_state['agent_results']['decision_agent']
        assert result['action'] == 'block_ip'
        assert result['confidence'] == 0.85
        assert 'fuerza bruta' in result['reasoning'].lower()
    
    def test_execute_attack_known_suspicious_activity(self):
        """Test de ejecución con actividad sospechosa."""
        # Estado con actividad sospechosa
        state: LangGraphAgentState = {
            'logs': [{
                'session_id': 'test', 
                'unusual_time_access': 1,
                'ip_reputation_score': 0.2,
                'encryption_used': 'DES'
            }],
            'agent_results': {
                'supervised_agent': {
                    'decision': 'attack_known',
                    'threat_level': 'medium',
                    'confidence': 0.8
                },
                'unsupervised_agent': {
                    'anomaly_score': 0.4,
                    'is_anomalous': False
                }
            },
            'execution_path': []
        }
        
        result_state = self.agent.execute(state)
        
        result = result_state['agent_results']['decision_agent']
        assert result['action'] == 'alert_security_team'
        assert result['confidence'] == 0.8
        assert 'sospechosa' in result['reasoning'].lower()
    
    def test_execute_attack_known_high_risk(self):
        """Test de ejecución con ataque de alto riesgo."""
        # Estado con alto riesgo (brute force + suspicious)
        state: LangGraphAgentState = {
            'logs': [{
                'session_id': 'test',
                'failed_logins': 4,
                'login_attempts': 6,
                'unusual_time_access': 1,
                'ip_reputation_score': 0.3
            }],
            'agent_results': {
                'supervised_agent': {
                    'decision': 'attack_known',
                    'threat_level': 'high',
                    'confidence': 0.9
                },
                'unsupervised_agent': {
                    'anomaly_score': 0.5,
                    'is_anomalous': False
                }
            },
            'execution_path': []
        }
        
        result_state = self.agent.execute(state)
        
        result = result_state['agent_results']['decision_agent']
        assert result['action'] == 'block_and_alert'
        assert result['confidence'] == 0.9
        assert 'alto riesgo' in result['reasoning'].lower()
    
    def test_execute_anomaly_detected_high_score(self):
        """Test de ejecución con anomalía detectada (score alto)."""
        # Estado con anomalía de score alto
        state: LangGraphAgentState = {
            'logs': [{'session_id': 'test', 'failed_logins': 0}],
            'agent_results': {
                'supervised_agent': {
                    'decision': 'normal',
                    'threat_level': 'low',
                    'confidence': 0.8
                },
                'unsupervised_agent': {
                    'anomaly_score': 0.8,
                    'is_anomalous': True
                }
            },
            'execution_path': []
        }
        
        result_state = self.agent.execute(state)
        
        result = result_state['agent_results']['decision_agent']
        assert result['action'] == 'alert_security_team'
        assert result['confidence'] == 0.75
        assert 'anomalía' in result['reasoning'].lower()
    
    def test_execute_anomaly_detected_low_score(self):
        """Test de ejecución con anomalía detectada (score bajo)."""
        # Estado con anomalía de score bajo
        state: LangGraphAgentState = {
            'logs': [{'session_id': 'test', 'failed_logins': 0}],
            'agent_results': {
                'supervised_agent': {
                    'decision': 'normal',
                    'threat_level': 'low',
                    'confidence': 0.8
                },
                'unsupervised_agent': {
                    'anomaly_score': 0.6,
                    'is_anomalous': True
                }
            },
            'execution_path': []
        }
        
        result_state = self.agent.execute(state)
        
        result = result_state['agent_results']['decision_agent']
        assert result['action'] == 'monitor_closely'
        assert result['confidence'] == 0.6
        assert 'anomalía menor' in result['reasoning'].lower()
    
    def test_execute_false_alarm_detection(self):
        """Test de detección de falsa alarma."""
        # Estado que debería ser falsa alarma
        state: LangGraphAgentState = {
            'logs': [{
                'session_id': 'test',
                'failed_logins': 0,
                'ip_reputation_score': 0.8,
                'unusual_time_access': 0,
                'encryption_used': 'AES',
                'browser_type': 'Chrome',
                'protocol_type': 'TCP',
                'session_duration': 600
            }],
            'agent_results': {
                'supervised_agent': {
                    'decision': 'attack_known',  # Modelo detecta ataque
                    'threat_level': 'medium',
                    'confidence': 0.7
                },
                'unsupervised_agent': {
                    'anomaly_score': 0.3,
                    'is_anomalous': False
                }
            },
            'execution_path': []
        }
        
        result_state = self.agent.execute(state)
        
        result = result_state['agent_results']['decision_agent']
        assert result['action'] == 'monitor'
        assert 'falsa alarma' in result['reasoning'].lower()
    
    def test_execute_default_case(self):
        """Test de caso por defecto (escalar)."""
        # Estado ambiguo
        state: LangGraphAgentState = {
            'logs': [{'session_id': 'test'}],
            'agent_results': {
                'supervised_agent': {
                    'decision': 'normal',
                    'threat_level': 'low',
                    'confidence': 0.5
                },
                'unsupervised_agent': {
                    'anomaly_score': 0.4,
                    'is_anomalous': False
                }
            },
            'execution_path': []
        }
        
        result_state = self.agent.execute(state)
        
        result = result_state['agent_results']['decision_agent']
        assert result['action'] == 'escalate'
        assert result['confidence'] == 0.7
        assert 'no clasificada' in result['reasoning'].lower()
    
    def test_classify_threat_type_brute_force(self):
        """Test de clasificación de tipo de amenaza - fuerza bruta."""
        logs = [
            {'failed_logins': 4, 'login_attempts': 6},
            {'failed_logins': 3, 'login_attempts': 7}
        ]
        
        threat_type = self.agent._classify_threat_type(logs)
        assert threat_type == 'brute_force'
    
    def test_classify_threat_type_suspicious_activity(self):
        """Test de clasificación de tipo de amenaza - actividad sospechosa."""
        logs = [
            {'unusual_time_access': 1, 'ip_reputation_score': 0.2, 'encryption_used': 'DES'}
        ]
        
        threat_type = self.agent._classify_threat_type(logs)
        assert threat_type == 'suspicious_activity'
    
    def test_classify_threat_type_high_risk(self):
        """Test de clasificación de tipo de amenaza - alto riesgo."""
        logs = [
            {'failed_logins': 3, 'unusual_time_access': 1, 'ip_reputation_score': 0.3}
        ]
        
        threat_type = self.agent._classify_threat_type(logs)
        assert threat_type == 'high_risk'
    
    def test_classify_threat_type_unknown(self):
        """Test de clasificación de tipo de amenaza - desconocido."""
        logs = [{'session_id': 'test'}]  # Sin indicadores claros
        
        threat_type = self.agent._classify_threat_type(logs)
        assert threat_type == 'unknown'
    
    def test_check_false_alarm_true(self):
        """Test de verificación de falsa alarma - verdadero."""
        logs = [{
            'ip_reputation_score': 0.8,
            'failed_logins': 0,
            'unusual_time_access': 0,
            'encryption_used': 'AES',
            'browser_type': 'Chrome',
            'protocol_type': 'TCP',
            'session_duration': 600
        }]
        
        result = self.agent._check_false_alarm(logs)
        assert result['is_false_alarm'] == True
        assert 'reputación' in result['reason']
    
    def test_check_false_alarm_false(self):
        """Test de verificación de falsa alarma - falso."""
        logs = [{
            'ip_reputation_score': 0.2,
            'failed_logins': 5,
            'unusual_time_access': 1,
            'encryption_used': 'None'
        }]
        
        result = self.agent._check_false_alarm(logs)
        assert result['is_false_alarm'] == False
    
    def test_map_llm_action_to_decision_action(self):
        """Test de mapeo de acciones LLM a acciones de decisión."""
        # Casos válidos
        assert self.agent._map_llm_action_to_decision_action('monitor') == 'monitor'
        assert self.agent._map_llm_action_to_decision_action('investigate') == 'investigate'
        assert self.agent._map_llm_action_to_decision_action('alert') == 'alert_security_team'
        assert self.agent._map_llm_action_to_decision_action('block') == 'block_ip'
        assert self.agent._map_llm_action_to_decision_action('block_and_alert') == 'block_and_alert'
        
        # Caso inválido
        assert self.agent._map_llm_action_to_decision_action('unknown') == 'investigate'
    
    def test_execute_with_empty_logs(self):
        """Test de ejecución con logs vacíos."""
        state: LangGraphAgentState = {
            'logs': [],
            'agent_results': {
                'supervised_agent': {
                    'decision': 'normal',
                    'threat_level': 'low',
                    'confidence': 0.8
                },
                'unsupervised_agent': {
                    'anomaly_score': 0.0,
                    'is_anomalous': False
                }
            },
            'execution_path': []
        }
        
        result_state = self.agent.execute(state)
        
        result = result_state['agent_results']['decision_agent']
        assert result['action'] == 'monitor'
    
    def test_execute_with_missing_agent_results(self):
        """Test de ejecución con resultados de agentes faltantes."""
        state: LangGraphAgentState = {
            'logs': [{'session_id': 'test'}],
            'agent_results': {},  # Sin resultados de agentes
            'execution_path': []
        }
        
        result_state = self.agent.execute(state)
        
        result = result_state['agent_results']['decision_agent']
        assert result['action'] == 'monitor'  # Comportamiento por defecto
