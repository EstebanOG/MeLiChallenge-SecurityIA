import pytest
from unittest.mock import Mock, patch
from datetime import datetime
import uuid

from src.domain.entities.agent import AgentContext, AgentType, AgentStatus
from src.domain.entities.pipeline import PipelineConfig, PipelineType, PipelineStatus
from src.infrastructure.orchestration.langgraph_orchestrator import LangGraphOrchestrator
from src.infrastructure.orchestration.agent_executors import (
    IngestionAgentExecutor, AnalysisAgentExecutor, DecisionAgentExecutor
)
from src.infrastructure.orchestration.agent_registry import InMemoryAgentRegistry
from src.infrastructure.orchestration.pipeline_state_manager import LangGraphPipelineStateManager
from src.application.use_cases.execute_threat_detection_pipeline import ExecuteThreatDetectionPipeline


class TestPipelineIntegration:
    """Tests de integración para pipelines completos."""
    
    @pytest.fixture
    def sample_logs(self):
        """Logs de ejemplo para testing."""
        return [
            {
                "timestamp": "2024-01-01T00:00:00Z",
                "device_id": "device_001",
                "device_type": "sensor",
                "cpu_usage": 45.5,
                "memory_usage": 60.2,
                "network_in_kb": 1024,
                "network_out_kb": 512,
                "packet_rate": 100,
                "avg_response_time_ms": 50.0,
                "service_access_count": 10,
                "failed_auth_attempts": 0,
                "is_encrypted": 1,
                "geo_location_variation": 0.1
            },
            {
                "timestamp": "2024-01-01T00:01:00Z",
                "device_id": "device_002",
                "device_type": "camera",
                "cpu_usage": 80.0,
                "memory_usage": 90.0,
                "network_in_kb": 2048,
                "network_out_kb": 1024,
                "packet_rate": 200,
                "avg_response_time_ms": 100.0,
                "service_access_count": 5,
                "failed_auth_attempts": 3,
                "is_encrypted": 0,
                "geo_location_variation": 0.5
            }
        ]
    
    @pytest.fixture
    def setup_orchestrator(self):
        """Configuración del orquestador para testing."""
        registry = InMemoryAgentRegistry()
        state_manager = LangGraphPipelineStateManager()
        
        # Registrar agentes
        registry.register_agent(AgentType.INGESTION, IngestionAgentExecutor())
        registry.register_agent(AgentType.ANALYSIS, AnalysisAgentExecutor())
        registry.register_agent(AgentType.DECISION, DecisionAgentExecutor())
        
        orchestrator = LangGraphOrchestrator(registry, state_manager)
        return orchestrator, registry, state_manager
    
    def test_threat_detection_pipeline_integration(self, setup_orchestrator, sample_logs):
        """Test de integración del pipeline de detección de amenazas."""
        
        orchestrator, registry, state_manager = setup_orchestrator
        
        # Crear configuración del pipeline
        config = PipelineConfig(
            pipeline_type=PipelineType.THREAT_DETECTION,
            agent_sequence=[
                AgentType.INGESTION,
                AgentType.ANALYSIS,
                AgentType.DECISION
            ],
            timeout_seconds=300,
            retry_attempts=3
        )
        
        # Ejecutar pipeline
        result = orchestrator.execute_pipeline(config, sample_logs)
        
        # Verificaciones
        assert result.status == PipelineStatus.COMPLETED
        assert result.execution_id is not None
        assert result.total_execution_time_ms > 0
        assert len(result.agent_results) == 3
        
        # Verificar que todos los agentes se ejecutaron
        agent_types = [result.agent_type for result in result.agent_results]
        assert AgentType.INGESTION in agent_types
        assert AgentType.ANALYSIS in agent_types
        assert AgentType.DECISION in agent_types
    
    def test_use_case_execution(self, setup_orchestrator, sample_logs):
        """Test de ejecución usando el caso de uso."""
        
        orchestrator, registry, state_manager = setup_orchestrator
        
        # Crear caso de uso
        use_case = ExecuteThreatDetectionPipeline(orchestrator, registry)
        
        # Ejecutar caso de uso
        result = use_case.execute(sample_logs)
        
        # Verificaciones
        assert result.status == PipelineStatus.COMPLETED
        assert result.pipeline_config.pipeline_type == PipelineType.THREAT_DETECTION
        assert len(result.agent_results) == 3
    
    def test_use_case_with_custom_context(self, setup_orchestrator, sample_logs):
        """Test de caso de uso con contexto personalizado."""
        
        orchestrator, registry, state_manager = setup_orchestrator
        use_case = ExecuteThreatDetectionPipeline(orchestrator, registry)
        
        # Ejecutar con contexto personalizado
        result = use_case.execute(
            sample_logs,
            trace_id="custom-trace-123",
            session_id="custom-session-456",
            custom_config={"priority": "high"}
        )
        
        # Verificaciones
        assert result.context.trace_id == "custom-trace-123"
        assert result.context.session_id == "custom-session-456"
        assert result.context.metadata["priority"] == "high"
    
    def test_use_case_with_notification(self, setup_orchestrator, sample_logs):
        """Test de caso de uso con notificaciones."""
        
        orchestrator, registry, state_manager = setup_orchestrator
        
        # Registrar agente de notificación
        from src.infrastructure.orchestration.agent_executors import NotificationAgentExecutor
        registry.register_agent(AgentType.NOTIFICATION, NotificationAgentExecutor())
        
        use_case = ExecuteThreatDetectionPipeline(orchestrator, registry)
        
        # Ejecutar con notificaciones
        result = use_case.execute_with_notification(
            sample_logs,
            notification_channels=["email", "slack"]
        )
        
        # Verificaciones
        assert result.status == PipelineStatus.COMPLETED
        assert len(result.agent_results) == 4  # Incluye notificación
        assert AgentType.NOTIFICATION in [r.agent_type for r in result.agent_results]
    
    def test_pipeline_with_invalid_config(self, setup_orchestrator, sample_logs):
        """Test de pipeline con configuración inválida."""
        
        orchestrator, registry, state_manager = setup_orchestrator
        
        # Configuración inválida
        config = PipelineConfig(
            pipeline_type=PipelineType.THREAT_DETECTION,
            agent_sequence=[],  # Secuencia vacía
            timeout_seconds=300
        )
        
        # Verificar validación
        errors = orchestrator.validate_pipeline_config(config)
        assert len(errors) > 0
        assert "secuencia de agentes no puede estar vacía" in errors[0]
    
    def test_pipeline_state_management(self, setup_orchestrator, sample_logs):
        """Test de manejo de estado del pipeline."""
        
        orchestrator, registry, state_manager = setup_orchestrator
        
        config = PipelineConfig(
            pipeline_type=PipelineType.THREAT_DETECTION,
            agent_sequence=[AgentType.INGESTION],
            timeout_seconds=300
        )
        
        context = AgentContext(
            trace_id="test-trace",
            session_id="test-session",
            created_at=datetime.utcnow(),
            metadata={"test": "metadata"}
        )
        
        # Crear estado inicial
        initial_state = state_manager.create_initial_state(sample_logs, config, context)
        
        # Verificaciones del estado inicial
        assert initial_state["trace_id"] == "test-trace"
        assert initial_state["session_id"] == "test-session"
        assert initial_state["pipeline_status"] == "pending"
        assert len(initial_state["logs"]) == 2
        
        # Simular resultado de agente
        agent_result = {
            "agent_type": "ingestion",
            "result": {
                "agent_type": "ingestion",
                "status": "completed",
                "output": {"received": 2},
                "execution_time_ms": 100.0
            },
            "status": "completed",
            "output": {"received": 2}
        }
        
        # Actualizar estado
        updated_state = state_manager.update_state(initial_state, agent_result)
        
        # Verificaciones del estado actualizado
        assert updated_state["pipeline_status"] == "completed"
        assert "ingestion" in updated_state["agent_results"]
        assert updated_state["current_agent"] == "ingestion"
        
        # Obtener resultado final
        final_result = state_manager.get_pipeline_result(updated_state)
        
        # Verificaciones del resultado final
        assert final_result["trace_id"] == "test-trace"
        assert final_result["pipeline_status"] == "completed"
        assert final_result["logs_processed"] == 2
        assert "ingestion" in final_result["agent_results"]
    
    @patch('src.infrastructure.orchestration.agent_executors.IsolationForestDetector')
    def test_analysis_agent_with_mock_detector(self, mock_detector_class, setup_orchestrator, sample_logs):
        """Test del agente de análisis con detector mockeado."""
        
        # Configurar mock del detector
        mock_detector = Mock()
        mock_detector.detect_anomalies.return_value = {
            "batch_score": 0.8,
            "threat_detected": True,
            "anomaly_scores": [0.7, 0.9],
            "confidence": 0.85
        }
        mock_detector_class.return_value = mock_detector
        
        orchestrator, registry, state_manager = setup_orchestrator
        
        # Crear configuración con solo análisis
        config = PipelineConfig(
            pipeline_type=PipelineType.THREAT_DETECTION,
            agent_sequence=[AgentType.INGESTION, AgentType.ANALYSIS],
            timeout_seconds=300
        )
        
        # Ejecutar pipeline
        result = orchestrator.execute_pipeline(config, sample_logs)
        
        # Verificaciones
        assert result.status == PipelineStatus.COMPLETED
        assert len(result.agent_results) == 2
        
        # Verificar que el detector fue llamado
        mock_detector.detect_anomalies.assert_called_once()
        
        # Verificar resultado del análisis
        analysis_result = result.get_agent_result(AgentType.ANALYSIS)
        assert analysis_result is not None
        assert analysis_result.status == AgentStatus.COMPLETED
        assert analysis_result.output["batch_score"] == 0.8
        assert analysis_result.output["threat_detected"] is True
    
    def test_pipeline_error_handling(self, setup_orchestrator, sample_logs):
        """Test de manejo de errores en el pipeline."""
        
        orchestrator, registry, state_manager = setup_orchestrator
        
        # Crear executor que falla
        failing_executor = Mock()
        failing_executor.can_handle.return_value = True
        failing_executor.execute.side_effect = Exception("Test error")
        
        # Registrar executor que falla
        registry.register_agent(AgentType.ANALYSIS, failing_executor)
        
        config = PipelineConfig(
            pipeline_type=PipelineType.THREAT_DETECTION,
            agent_sequence=[AgentType.INGESTION, AgentType.ANALYSIS],
            timeout_seconds=300
        )
        
        # Ejecutar pipeline
        result = orchestrator.execute_pipeline(config, sample_logs)
        
        # Verificar que el pipeline falló
        assert result.status == PipelineStatus.FAILED
        assert result.error_message is not None
        assert "Test error" in result.error_message
