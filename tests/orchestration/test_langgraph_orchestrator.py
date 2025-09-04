import pytest
from unittest.mock import Mock, patch
from datetime import datetime
import uuid

from src.domain.entities.agent import AgentContext, AgentType, AgentStatus
from src.domain.entities.pipeline import PipelineConfig, PipelineType, PipelineStatus
from src.domain.interfaces.agent_executor import AgentExecutor
from src.infrastructure.orchestration.langgraph_orchestrator import LangGraphOrchestrator
from src.infrastructure.orchestration.agent_executors import IngestionAgentExecutor
from src.infrastructure.orchestration.agent_registry import InMemoryAgentRegistry
from src.infrastructure.orchestration.pipeline_state_manager import LangGraphPipelineStateManager


class TestLangGraphOrchestrator:
    """Tests para el orquestador de LangGraph."""
    
    @pytest.fixture
    def mock_agent_executor(self):
        """Mock del executor de agentes."""
        executor = Mock(spec=AgentExecutor)
        executor.can_handle.return_value = True
        executor.execute.return_value = Mock(
            agent_type=AgentType.INGESTION,
            status=AgentStatus.COMPLETED,
            output={"test": "data"},
            execution_time_ms=100.0,
            confidence=0.9
        )
        return executor
    
    @pytest.fixture
    def agent_registry(self, mock_agent_executor):
        """Registry de agentes para testing."""
        registry = InMemoryAgentRegistry()
        registry.register_agent(AgentType.INGESTION, mock_agent_executor)
        return registry
    
    @pytest.fixture
    def state_manager(self):
        """Manejador de estado para testing."""
        return LangGraphPipelineStateManager()
    
    @pytest.fixture
    def orchestrator(self, agent_registry, state_manager):
        """Orquestador para testing."""
        return LangGraphOrchestrator(agent_registry, state_manager)
    
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
            }
        ]
    
    @pytest.fixture
    def pipeline_config(self):
        """Configuración de pipeline para testing."""
        return PipelineConfig(
            pipeline_type=PipelineType.THREAT_DETECTION,
            agent_sequence=[AgentType.INGESTION],
            timeout_seconds=300,
            retry_attempts=3
        )
    
    def test_execute_pipeline_success(self, orchestrator, sample_logs, pipeline_config):
        """Test de ejecución exitosa de pipeline."""
        
        result = orchestrator.execute_pipeline(pipeline_config, sample_logs)
        
        assert result.status == PipelineStatus.COMPLETED
        assert result.execution_id is not None
        assert result.total_execution_time_ms > 0
        assert len(result.agent_results) == 1
    
    def test_execute_pipeline_with_context(self, orchestrator, sample_logs, pipeline_config):
        """Test de ejecución de pipeline con contexto personalizado."""
        
        context = AgentContext(
            trace_id="test-trace-123",
            session_id="test-session-456",
            created_at=datetime.utcnow(),
            metadata={"test": "metadata"}
        )
        
        result = orchestrator.execute_pipeline(pipeline_config, sample_logs, context)
        
        assert result.context.trace_id == "test-trace-123"
        assert result.context.session_id == "test-session-456"
        assert result.context.metadata["test"] == "metadata"
    
    def test_validate_pipeline_config_valid(self, orchestrator, pipeline_config):
        """Test de validación de configuración válida."""
        
        errors = orchestrator.validate_pipeline_config(pipeline_config)
        assert len(errors) == 0
    
    def test_validate_pipeline_config_invalid_sequence(self, orchestrator):
        """Test de validación de configuración con secuencia inválida."""
        
        config = PipelineConfig(
            pipeline_type=PipelineType.THREAT_DETECTION,
            agent_sequence=[],  # Secuencia vacía
            timeout_seconds=300
        )
        
        errors = orchestrator.validate_pipeline_config(config)
        assert len(errors) > 0
        assert "secuencia de agentes no puede estar vacía" in errors[0]
    
    def test_validate_pipeline_config_invalid_timeout(self, orchestrator):
        """Test de validación de configuración con timeout inválido."""
        
        config = PipelineConfig(
            pipeline_type=PipelineType.THREAT_DETECTION,
            agent_sequence=[AgentType.INGESTION],
            timeout_seconds=-1  # Timeout inválido
        )
        
        errors = orchestrator.validate_pipeline_config(config)
        assert len(errors) > 0
        assert "timeout debe ser mayor a 0" in errors[0]
    
    def test_execute_step_success(self, orchestrator, sample_logs, pipeline_config):
        """Test de ejecución de paso individual."""
        
        context = AgentContext(
            trace_id="test-trace",
            session_id="test-session",
            created_at=datetime.utcnow(),
            metadata={}
        )
        
        initial_state = orchestrator.state_manager.create_initial_state(
            sample_logs, pipeline_config, context
        )
        
        result_state = orchestrator.execute_step(initial_state, "ingestion")
        
        assert "ingestion" in result_state["agent_results"]
        assert result_state["current_agent"] == "ingestion"
    
    def test_execute_step_unknown_agent(self, orchestrator, sample_logs, pipeline_config):
        """Test de ejecución de paso con agente desconocido."""
        
        context = AgentContext(
            trace_id="test-trace",
            session_id="test-session",
            created_at=datetime.utcnow(),
            metadata={}
        )
        
        initial_state = orchestrator.state_manager.create_initial_state(
            sample_logs, pipeline_config, context
        )
        
        with pytest.raises(ValueError, match="No se encontró executor para el agente"):
            orchestrator.execute_step(initial_state, "unknown_agent")
    
    @patch('src.infrastructure.orchestration.langgraph_orchestrator.StateGraph')
    def test_build_graph(self, mock_state_graph, orchestrator, pipeline_config):
        """Test de construcción del grafo."""
        
        mock_graph_instance = Mock()
        mock_state_graph.return_value = mock_graph_instance
        mock_graph_instance.compile.return_value = Mock()
        
        orchestrator._build_graph(pipeline_config)
        
        # Verificar que se agregaron los nodos
        assert mock_graph_instance.add_node.call_count == 1
        assert mock_graph_instance.add_edge.call_count == 2  # START->agent, agent->END
    
    def test_extract_agent_results(self, orchestrator):
        """Test de extracción de resultados de agentes."""
        
        state = {
            "agent_results": {
                "ingestion": {
                    "agent_type": "ingestion",
                    "status": "completed",
                    "output": {"test": "data"},
                    "execution_time_ms": 100.0,
                    "confidence": 0.9
                }
            }
        }
        
        results = orchestrator._extract_agent_results(state)
        
        assert len(results) == 1
        assert results[0].agent_type == AgentType.INGESTION
        assert results[0].status == AgentStatus.COMPLETED


class TestAgentExecutors:
    """Tests para los executors de agentes."""
    
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
            }
        ]
    
    @pytest.fixture
    def context(self):
        """Contexto para testing."""
        return AgentContext(
            trace_id="test-trace",
            session_id="test-session",
            created_at=datetime.utcnow(),
            metadata={}
        )
    
    def test_ingestion_agent_executor_success(self, sample_logs, context):
        """Test de ejecución exitosa del agente de ingesta."""
        
        executor = IngestionAgentExecutor()
        state = {"logs": sample_logs}
        
        result = executor.execute(AgentType.INGESTION, state, context)
        
        assert result.agent_type == AgentType.INGESTION
        assert result.status == AgentStatus.COMPLETED
        assert result.is_successful
        assert "trace_id" in result.output
        assert result.output["received"] == 1
    
    def test_ingestion_agent_executor_invalid_data(self, context):
        """Test de ejecución del agente de ingesta con datos inválidos."""
        
        executor = IngestionAgentExecutor()
        invalid_logs = [{"invalid": "data"}]  # Faltan campos requeridos
        state = {"logs": invalid_logs}
        
        result = executor.execute(AgentType.INGESTION, state, context)
        
        assert result.agent_type == AgentType.INGESTION
        assert result.status == AgentStatus.COMPLETED
        assert result.output["received"] == 0
        assert len(result.output["validation_errors"]) > 0
    
    def test_ingestion_agent_executor_can_handle(self):
        """Test de verificación de capacidad del agente de ingesta."""
        
        executor = IngestionAgentExecutor()
        
        assert executor.can_handle(AgentType.INGESTION)
        assert not executor.can_handle(AgentType.ANALYSIS)


class TestAgentRegistry:
    """Tests para el registro de agentes."""
    
    def test_register_agent(self):
        """Test de registro de agente."""
        
        registry = InMemoryAgentRegistry()
        executor = Mock(spec=AgentExecutor)
        executor.can_handle.return_value = True
        
        registry.register_agent(AgentType.INGESTION, executor)
        
        assert registry.is_registered(AgentType.INGESTION)
        assert registry.get_executor(AgentType.INGESTION) == executor
    
    def test_register_incompatible_agent(self):
        """Test de registro de agente incompatible."""
        
        registry = InMemoryAgentRegistry()
        executor = Mock(spec=AgentExecutor)
        executor.can_handle.return_value = False  # No puede manejar el agente
        
        with pytest.raises(ValueError, match="no puede manejar el tipo de agente"):
            registry.register_agent(AgentType.INGESTION, executor)
    
    def test_get_nonexistent_agent(self):
        """Test de obtención de agente no existente."""
        
        registry = InMemoryAgentRegistry()
        
        assert registry.get_executor(AgentType.INGESTION) is None
    
    def test_list_available_agents(self):
        """Test de listado de agentes disponibles."""
        
        registry = InMemoryAgentRegistry()
        executor = Mock(spec=AgentExecutor)
        executor.can_handle.return_value = True
        
        registry.register_agent(AgentType.INGESTION, executor)
        registry.register_agent(AgentType.ANALYSIS, executor)
        
        available = registry.list_available_agents()
        
        assert AgentType.INGESTION in available
        assert AgentType.ANALYSIS in available
        assert len(available) == 2
    
    def test_unregister_agent(self):
        """Test de desregistro de agente."""
        
        registry = InMemoryAgentRegistry()
        executor = Mock(spec=AgentExecutor)
        executor.can_handle.return_value = True
        
        registry.register_agent(AgentType.INGESTION, executor)
        assert registry.is_registered(AgentType.INGESTION)
        
        success = registry.unregister_agent(AgentType.INGESTION)
        assert success
        assert not registry.is_registered(AgentType.INGESTION)
        
        # Intentar desregistrar agente no existente
        success = registry.unregister_agent(AgentType.ANALYSIS)
        assert not success
