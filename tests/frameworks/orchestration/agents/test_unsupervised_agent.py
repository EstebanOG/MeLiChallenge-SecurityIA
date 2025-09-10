"""
Tests para el UnsupervisedAgent.

Prueba la funcionalidad del agente no supervisado que detecta anomalías
usando técnicas de machine learning.
"""

import pytest
from unittest.mock import Mock, patch
from src.frameworks.orchestration.agents.unsupervised_agent import UnsupervisedAgent
from src.application.interfaces.anomaly_detector import AnomalyDetector, AnomalyResult
from src.domain.entities.log_entry import LogEntry


class TestUnsupervisedAgent:
    """Tests para el UnsupervisedAgent."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.mock_anomaly_detector = Mock(spec=AnomalyDetector)
        self.agent = UnsupervisedAgent(self.mock_anomaly_detector)
    
    def test_init_with_detector(self):
        """Test de inicialización con detector."""
        assert self.agent.name == "unsupervised_agent"
        assert self.agent.anomaly_detector == self.mock_anomaly_detector
    
    def test_init_without_detector(self):
        """Test de inicialización sin detector."""
        agent = UnsupervisedAgent()
        assert agent.name == "unsupervised_agent"
        assert agent.anomaly_detector is None
    
    def test_execute_with_ml_detector_anomaly_detected(self):
        """Test de ejecución con detector ML cuando se detecta anomalía."""
        # Configurar mocks
        logs = [
            {
                'session_id': 'SID_001',
                'network_packet_size': 800,
                'protocol_type': 'TCP',
                'login_attempts': 8,
                'session_duration': 2000.0,
                'encryption_used': 'AES',
                'ip_reputation_score': 0.1,
                'failed_logins': 5,
                'browser_type': 'Unknown',
                'unusual_time_access': 1,
                'attack_detected': 1
            }
        ]
        
        state = {"logs": logs}
        
        anomaly_result = AnomalyResult(
            batch_score=0.85,
            threat_detected=True,
            anomaly_scores=[0.85],
            confidence=0.9
        )
        
        self.mock_anomaly_detector.is_ready.return_value = True
        self.mock_anomaly_detector.detect_anomalies.return_value = anomaly_result
        
        # Ejecutar
        result = self.agent.execute(state)
        
        # Verificar
        assert result["logs"] == logs
        assert "execution_steps" in result
        assert len(result["execution_steps"]) == 1
        
        step = result["execution_steps"][0]
        assert step["agent"] == "unsupervised_agent"
        assert step["decision"] == "anomalous"
        assert step["anomaly_score"] == 0.85
        assert step["confidence"] == 0.9
        assert step["threat_level"] == "critical"
        assert step["next_agent"] == "decision_agent"
        assert "Detectadas 1 anomalías de 1 logs" in step["reasoning"]
        
        # Verificar que se llamó al detector
        self.mock_anomaly_detector.detect_anomalies.assert_called_once()
    
    def test_execute_with_ml_detector_no_anomaly(self):
        """Test de ejecución con detector ML cuando no se detecta anomalía."""
        # Configurar mocks
        logs = [
            {
                'session_id': 'SID_002',
                'network_packet_size': 400,
                'protocol_type': 'TCP',
                'login_attempts': 2,
                'session_duration': 300.0,
                'encryption_used': 'AES',
                'ip_reputation_score': 0.8,
                'failed_logins': 0,
                'browser_type': 'Chrome',
                'unusual_time_access': 0,
                'attack_detected': 0
            }
        ]
        
        state = {"logs": logs}
        
        anomaly_result = AnomalyResult(
            batch_score=0.15,
            threat_detected=False,
            anomaly_scores=[0.15],
            confidence=0.9
        )
        
        self.mock_anomaly_detector.is_ready.return_value = True
        self.mock_anomaly_detector.detect_anomalies.return_value = anomaly_result
        
        # Ejecutar
        result = self.agent.execute(state)
        
        # Verificar
        assert result["logs"] == logs
        assert "execution_steps" in result
        assert len(result["execution_steps"]) == 1
        
        step = result["execution_steps"][0]
        assert step["agent"] == "unsupervised_agent"
        assert step["decision"] == "normal"
        assert step["anomaly_score"] == 0.15
        assert step["confidence"] == 0.9
        assert step["threat_level"] == "low"
        assert step["next_agent"] == "report_agent"
        assert "No se detectaron anomalías significativas" in step["reasoning"]
    
    def test_execute_without_ml_detector_fallback(self):
        """Test de ejecución sin detector ML usando fallback."""
        # Configurar mocks
        logs = [
            {
                'session_id': 'SID_003',
                'network_packet_size': 900,
                'protocol_type': 'UDP',
                'login_attempts': 7,
                'session_duration': 1800.0,
                'encryption_used': 'DES',
                'ip_reputation_score': 0.15,
                'failed_logins': 4,
                'browser_type': 'Unknown',
                'unusual_time_access': 1,
                'attack_detected': 1
            }
        ]
        
        state = {"logs": logs}
        
        # Sin detector ML
        agent = UnsupervisedAgent()
        
        # Ejecutar
        result = agent.execute(state)
        
        # Verificar
        assert result["logs"] == logs
        assert "execution_steps" in result
        assert len(result["execution_steps"]) == 1
        
        step = result["execution_steps"][0]
        assert step["agent"] == "unsupervised_agent"
        assert step["decision"] == "anomalous"  # Debería detectar anomalía por reglas
        assert step["anomaly_score"] > 0.3  # Score alto por reglas heurísticas
        assert step["next_agent"] == "decision_agent"
    
    def test_execute_empty_logs(self):
        """Test de ejecución con logs vacíos."""
        state = {"logs": []}
        
        # Ejecutar
        result = self.agent.execute(state)
        
        # Verificar
        assert result["logs"] == []
        assert "execution_steps" in result
        assert len(result["execution_steps"]) == 1
        
        step = result["execution_steps"][0]
        assert step["decision"] == "normal"
        assert step["anomaly_score"] == 0.0
    
    def test_convert_to_log_entries_success(self):
        """Test de conversión exitosa de logs a LogEntry."""
        logs = [
            {
                'session_id': 'SID_001',
                'network_packet_size': 500,
                'protocol_type': 'TCP',
                'login_attempts': 3,
                'session_duration': 600.0,
                'encryption_used': 'AES',
                'ip_reputation_score': 0.7,
                'failed_logins': 1,
                'browser_type': 'Chrome',
                'unusual_time_access': 0,
                'attack_detected': 0
            }
        ]
        
        # Ejecutar
        log_entries = self.agent._convert_to_log_entries(logs)
        
        # Verificar
        assert len(log_entries) == 1
        entry = log_entries[0]
        assert isinstance(entry, LogEntry)
        assert entry.session_id == 'SID_001'
        assert entry.network_packet_size == 500
        assert entry.protocol_type == 'TCP'
        assert entry.login_attempts == 3
        assert entry.session_duration == 600.0
        assert entry.encryption_used == 'AES'
        assert entry.ip_reputation_score == 0.7
        assert entry.failed_logins == 1
        assert entry.browser_type == 'Chrome'
        assert entry.unusual_time_access is False
        assert entry.attack_detected is False
    
    def test_convert_to_log_entries_with_errors(self):
        """Test de conversión con errores en algunos logs."""
        logs = [
            {
                'session_id': 'SID_001',
                'network_packet_size': 500,
                'protocol_type': 'TCP',
                'login_attempts': 3,
                'session_duration': 600.0,
                'encryption_used': 'AES',
                'ip_reputation_score': 0.7,
                'failed_logins': 1,
                'browser_type': 'Chrome',
                'unusual_time_access': 0,
                'attack_detected': 0
            },
            {
                'session_id': 'SID_002',
                'network_packet_size': 'invalid',  # Error de tipo
                'protocol_type': 'TCP',
                'login_attempts': 3,
                'session_duration': 600.0,
                'encryption_used': 'AES',
                'ip_reputation_score': 0.7,
                'failed_logins': 1,
                'browser_type': 'Chrome',
                'unusual_time_access': 0,
                'attack_detected': 0
            }
        ]
        
        # Ejecutar
        log_entries = self.agent._convert_to_log_entries(logs)
        
        # Verificar que solo se procesó el log válido
        assert len(log_entries) == 1
        assert log_entries[0].session_id == 'SID_001'
    
    def test_detect_anomalies_fallback_high_anomaly_score(self):
        """Test de detección de anomalías con fallback - score alto."""
        logs = [
            {
                'session_id': 'SID_001',
                'network_packet_size': 900,  # Paquete grande
                'protocol_type': 'UDP',
                'login_attempts': 8,  # Muchos intentos
                'session_duration': 2000.0,  # Sesión larga
                'encryption_used': 'DES',
                'ip_reputation_score': 0.1,  # Reputación muy baja
                'failed_logins': 5,  # Muchos fallos
                'browser_type': 'Unknown',
                'unusual_time_access': 1,
                'attack_detected': 1
            }
        ]
        
        # Ejecutar
        is_anomalous, score, confidence = self.agent._detect_anomalies_fallback(logs)
        
        # Verificar
        assert is_anomalous is True
        assert score > 0.3  # Debería ser alto por múltiples indicadores
        assert confidence == 0.7
    
    def test_detect_anomalies_fallback_low_anomaly_score(self):
        """Test de detección de anomalías con fallback - score bajo."""
        logs = [
            {
                'session_id': 'SID_002',
                'network_packet_size': 400,
                'protocol_type': 'TCP',
                'login_attempts': 2,
                'session_duration': 300.0,
                'encryption_used': 'AES',
                'ip_reputation_score': 0.8,
                'failed_logins': 0,
                'browser_type': 'Chrome',
                'unusual_time_access': 0,
                'attack_detected': 0
            }
        ]
        
        # Ejecutar
        is_anomalous, score, confidence = self.agent._detect_anomalies_fallback(logs)
        
        # Verificar
        assert is_anomalous is False
        assert score < 0.3  # Debería ser bajo
        assert confidence == 0.9
    
    def test_determine_threat_level(self):
        """Test de determinación del nivel de amenaza."""
        # Critical
        assert self.agent._determine_threat_level(0.9) == "critical"
        assert self.agent._determine_threat_level(0.8) == "critical"
        
        # High
        assert self.agent._determine_threat_level(0.7) == "high"
        assert self.agent._determine_threat_level(0.6) == "high"
        
        # Medium
        assert self.agent._determine_threat_level(0.5) == "medium"
        assert self.agent._determine_threat_level(0.4) == "medium"
        
        # Low
        assert self.agent._determine_threat_level(0.3) == "low"
        assert self.agent._determine_threat_level(0.1) == "low"
