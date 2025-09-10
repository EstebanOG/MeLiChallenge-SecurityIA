"""
Tests para el AnalyzeThreatLogsUseCase.

Prueba la funcionalidad del caso de uso que maneja el análisis
de logs de threat intelligence usando el pipeline de agentes.
"""

import pytest
from unittest.mock import Mock, patch
from src.application.use_cases.analyze_logs import AnalyzeThreatLogsUseCase
from src.application.interfaces.pipeline_orchestrator import PipelineOrchestrator
from src.application.interfaces.supervised_model_interface import SupervisedModelInterface
from src.domain.entities.dto import ThreatAnalyzeRequestDTO, ThreatAnalyzeResponseDTO
from src.domain.entities.agent import AgentType


class TestAnalyzeThreatLogsUseCase:
    """Tests para el AnalyzeThreatLogsUseCase."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        # Mock del orquestador
        self.mock_orchestrator = Mock(spec=PipelineOrchestrator)
        # Mock del modelo supervisado
        self.mock_supervised_model = Mock(spec=SupervisedModelInterface)
        self.use_case = AnalyzeThreatLogsUseCase(self.mock_orchestrator, self.mock_supervised_model)
    
    def test_init_with_orchestrator_and_model(self):
        """Test de inicialización con orquestador y modelo."""
        assert self.use_case.orchestrator == self.mock_orchestrator
        assert self.use_case.supervised_model == self.mock_supervised_model
        assert self.use_case.supervised_model_path == "models/supervised_model.joblib"
    
    def test_init_with_orchestrator_only(self):
        """Test de inicialización solo con orquestador."""
        use_case = AnalyzeThreatLogsUseCase(self.mock_orchestrator)
        assert use_case.orchestrator == self.mock_orchestrator
        assert use_case.supervised_model is None
    
    def test_execute_success(self):
        """Test de ejecución exitosa del análisis."""
        # Configurar mocks
        self.mock_supervised_model.is_trained.return_value = True
        
        # Crear mocks de los resultados de agentes
        mock_supervised_result = Mock()
        mock_supervised_result.output = {
            "decision": "attack_known",
            "confidence": 0.85,
            "threat_level": "high"
        }
        
        mock_unsupervised_result = Mock()
        mock_unsupervised_result.output = {
            "decision": "normal",
            "confidence": 0.70
        }
        
        mock_decision_result = Mock()
        mock_decision_result.output = {
            "action": "block",
            "confidence": 0.85,
            "reasoning": "Ataque detectado con alta confianza"
        }
        
        mock_report_result = Mock()
        mock_report_result.output = {
            "message": "Análisis completado exitosamente"
        }
        
        # Crear mock del resultado de ejecución
        mock_execution_result = Mock()
        mock_execution_result.get_agent_result.side_effect = lambda agent_type: {
            AgentType.INGESTION: mock_supervised_result,
            AgentType.ANALYSIS: mock_unsupervised_result,
            AgentType.DECISION: mock_decision_result,
            AgentType.NOTIFICATION: mock_report_result
        }.get(agent_type)
        mock_execution_result.context.trace_id = "exec_123"
        
        self.mock_orchestrator.execute_pipeline.return_value = mock_execution_result
        
        # Datos de entrada
        request = ThreatAnalyzeRequestDTO(
            logs=[
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
        )
        
        # Ejecutar
        result = self.use_case.execute(request)
        
        # Verificar
        assert result.trace_id == "exec_123"
        assert result.score == 0.8  # threat_detected = True
        assert result.decision["action"] == "block"
        assert result.decision["confidence"] == 0.85
        assert result.decision["threat_detected"] == True
        assert result.decision["anomaly_detected"] == False
        assert "Ataque detectado con alta confianza" in result.decision["reasoning"]
        assert result.batch_size == 1
        
        # Verificar que se llamaron los métodos
        self.mock_supervised_model.is_trained.assert_called_once()
        self.mock_orchestrator.execute_pipeline.assert_called_once()
    
    def test_execute_model_not_trained_raises_error(self):
        """Test de error cuando el modelo no está entrenado."""
        # Configurar mock
        self.mock_supervised_model.is_trained.return_value = False
        
        # Datos de entrada
        request = ThreatAnalyzeRequestDTO(
            logs=[{
                "session_id": "test", 
                "network_packet_size": 500,
                "protocol_type": "TCP",
                "login_attempts": 3,
                "session_duration": 300.0,
                "encryption_used": "AES",
                "ip_reputation_score": 0.2,
                "failed_logins": 3,
                "browser_type": "Chrome",
                "unusual_time_access": 0
            }]
        )
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(ValueError, match="El modelo supervisado no está entrenado"):
            self.use_case.execute(request)
    
    def test_execute_without_supervised_model_raises_error(self):
        """Test de error cuando no hay modelo supervisado."""
        # Crear caso de uso sin modelo supervisado
        use_case = AnalyzeThreatLogsUseCase(self.mock_orchestrator)
        
        # Datos de entrada
        request = ThreatAnalyzeRequestDTO(
            logs=[{
                "session_id": "test", 
                "network_packet_size": 500,
                "protocol_type": "TCP",
                "login_attempts": 3,
                "session_duration": 300.0,
                "encryption_used": "AES",
                "ip_reputation_score": 0.2,
                "failed_logins": 3,
                "browser_type": "Chrome",
                "unusual_time_access": 0
            }]
        )
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(ValueError, match="El modelo supervisado no está entrenado"):
            use_case.execute(request)
    
    def test_execute_orchestrator_error(self):
        """Test de error en el orquestador."""
        # Configurar mocks
        self.mock_supervised_model.is_trained.return_value = True
        self.mock_orchestrator.execute_pipeline.side_effect = Exception("Error en orquestador")
        
        # Datos de entrada
        request = ThreatAnalyzeRequestDTO(
            logs=[{
                "session_id": "test", 
                "network_packet_size": 500,
                "protocol_type": "TCP",
                "login_attempts": 3,
                "session_duration": 300.0,
                "encryption_used": "AES",
                "ip_reputation_score": 0.2,
                "failed_logins": 3,
                "browser_type": "Chrome",
                "unusual_time_access": 0
            }]
        )
        
        # Ejecutar y verificar que lanza error
        with pytest.raises(Exception, match="Error en orquestador"):
            self.use_case.execute(request)
    
    def test_execute_empty_logs(self):
        """Test de ejecución con logs vacíos."""
        # Configurar mocks
        self.mock_supervised_model.is_trained.return_value = True
        
        # Crear mocks de los resultados de agentes (todos None para logs vacíos)
        mock_execution_result = Mock()
        mock_execution_result.get_agent_result.return_value = None
        mock_execution_result.context.trace_id = "exec_empty"
        
        self.mock_orchestrator.execute_pipeline.return_value = mock_execution_result
        
        # Datos de entrada con logs vacíos
        request = ThreatAnalyzeRequestDTO(logs=[])
        
        # Ejecutar
        result = self.use_case.execute(request)
        
        # Verificar
        assert result.trace_id == "exec_empty"
        assert result.score == 0.2  # Sin amenazas detectadas
        assert result.decision["action"] == "monitor"
        assert result.decision["confidence"] == 0.0
        assert result.decision["threat_detected"] == False
        assert result.decision["anomaly_detected"] == False
        assert result.batch_size == 0
    
    def test_is_supervised_model_trained_true(self):
        """Test de verificación cuando el modelo está entrenado."""
        # Configurar mock
        self.mock_supervised_model.is_trained.return_value = True
        
        # Ejecutar
        result = self.use_case._is_supervised_model_trained()
        
        # Verificar
        assert result == True
        self.mock_supervised_model.is_trained.assert_called_once()
    
    def test_is_supervised_model_trained_false(self):
        """Test de verificación cuando el modelo no está entrenado."""
        # Configurar mock
        self.mock_supervised_model.is_trained.return_value = False
        
        # Ejecutar
        result = self.use_case._is_supervised_model_trained()
        
        # Verificar
        assert result == False
        self.mock_supervised_model.is_trained.assert_called_once()
    
    def test_is_supervised_model_trained_without_model(self):
        """Test de verificación cuando no hay modelo supervisado."""
        # Crear caso de uso sin modelo supervisado
        use_case = AnalyzeThreatLogsUseCase(self.mock_orchestrator)
        
        # Ejecutar
        result = use_case._is_supervised_model_trained()
        
        # Verificar
        assert result == False
