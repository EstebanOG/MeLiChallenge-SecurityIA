"""
Tests para el caso de uso AnalyzeIoTLogsUseCase.

Estos tests verifican la lógica de negocio para análisis de logs IoT.
"""

import pytest
from unittest.mock import Mock, MagicMock
from src.application.use_cases.analyze_iot_logs import AnalyzeIoTLogsUseCase
from src.domain.entities.dto import IoTAnalyzeRequestDTO, IoTLogItemDTO
from src.domain.entities.agent import AgentType, AgentResult, AgentContext
from src.domain.entities.pipeline import PipelineExecution, PipelineStatus


class TestAnalyzeIoTLogsUseCase:
    """Tests para AnalyzeIoTLogsUseCase."""
    
    def setup_method(self):
        """Setup para cada test."""
        self.mock_orchestrator = Mock()
        self.mock_agent_registry = Mock()
        self.use_case = AnalyzeIoTLogsUseCase(
            self.mock_orchestrator,
            self.mock_agent_registry
        )
    
    def test_execute_success(self):
        """Test ejecución exitosa del análisis."""
        # Arrange
        log_item = IoTLogItemDTO(
            timestamp="2024-01-01T00:00:00Z",
            device_id="device_001",
            device_type="thermostat",
            cpu_usage=50.0,
            memory_usage=60.0,
            network_in_kb=1000,
            network_out_kb=500,
            packet_rate=100,
            avg_response_time_ms=50.0,
            service_access_count=10,
            failed_auth_attempts=0,
            is_encrypted=1,
            geo_location_variation=0.1
        )
        
        request = IoTAnalyzeRequestDTO(logs=[log_item])
        
        # Mock pipeline execution result
        mock_context = AgentContext(
            trace_id="trace_123",
            session_id="session_123",
            created_at=None,
            metadata={}
        )
        
        mock_analysis_result = AgentResult(
            agent_type=AgentType.ANALYSIS,
            status="completed",
            output={"batch_score": 0.85},
            execution_time=1.5,
            error_message=None
        )
        
        mock_decision_result = AgentResult(
            agent_type=AgentType.DECISION,
            status="completed",
            output={"action": "block", "confidence": 0.9},
            execution_time=0.5,
            error_message=None
        )
        
        mock_execution = Mock(spec=PipelineExecution)
        mock_execution.context = mock_context
        mock_execution.get_agent_result.side_effect = lambda agent_type: {
            AgentType.ANALYSIS: mock_analysis_result,
            AgentType.DECISION: mock_decision_result
        }.get(agent_type)
        
        self.mock_orchestrator.execute_pipeline.return_value = mock_execution
        
        # Act
        result = self.use_case.execute(request)
        
        # Assert
        assert result.trace_id == "trace_123"
        assert result.score == 0.85
        assert result.decision["action"] == "block"
        assert result.batch_size == 1
        
        # Verificar que se llamó al orchestrator
        self.mock_orchestrator.execute_pipeline.assert_called_once()
        call_args = self.mock_orchestrator.execute_pipeline.call_args
        assert call_args[1]["logs"] == [log_item.model_dump()]
    
    def test_execute_with_empty_logs(self):
        """Test ejecución con lista vacía de logs."""
        # Arrange
        request = IoTAnalyzeRequestDTO(logs=[])
        
        mock_context = AgentContext(
            trace_id="trace_123",
            session_id="session_123",
            created_at=None,
            metadata={}
        )
        
        mock_execution = Mock(spec=PipelineExecution)
        mock_execution.context = mock_context
        mock_execution.get_agent_result.return_value = None
        
        self.mock_orchestrator.execute_pipeline.return_value = mock_execution
        
        # Act
        result = self.use_case.execute(request)
        
        # Assert
        assert result.trace_id == "trace_123"
        assert result.score == 0.0
        assert result.decision == {}
        assert result.batch_size == 0
    
    def test_execute_with_missing_analysis_result(self):
        """Test ejecución cuando falta el resultado de análisis."""
        # Arrange
        log_item = IoTLogItemDTO(
            timestamp="2024-01-01T00:00:00Z",
            device_id="device_001",
            device_type="thermostat",
            cpu_usage=50.0,
            memory_usage=60.0,
            network_in_kb=1000,
            network_out_kb=500,
            packet_rate=100,
            avg_response_time_ms=50.0,
            service_access_count=10,
            failed_auth_attempts=0,
            is_encrypted=1,
            geo_location_variation=0.1
        )
        
        request = IoTAnalyzeRequestDTO(logs=[log_item])
        
        mock_context = AgentContext(
            trace_id="trace_123",
            session_id="session_123",
            created_at=None,
            metadata={}
        )
        
        mock_execution = Mock(spec=PipelineExecution)
        mock_execution.context = mock_context
        mock_execution.get_agent_result.return_value = None
        
        self.mock_orchestrator.execute_pipeline.return_value = mock_execution
        
        # Act
        result = self.use_case.execute(request)
        
        # Assert
        assert result.trace_id == "trace_123"
        assert result.score == 0.0
        assert result.decision == {}
        assert result.batch_size == 1
    
    def test_execute_with_partial_results(self):
        """Test ejecución con resultados parciales."""
        # Arrange
        log_item = IoTLogItemDTO(
            timestamp="2024-01-01T00:00:00Z",
            device_id="device_001",
            device_type="thermostat",
            cpu_usage=50.0,
            memory_usage=60.0,
            network_in_kb=1000,
            network_out_kb=500,
            packet_rate=100,
            avg_response_time_ms=50.0,
            service_access_count=10,
            failed_auth_attempts=0,
            is_encrypted=1,
            geo_location_variation=0.1
        )
        
        request = IoTAnalyzeRequestDTO(logs=[log_item])
        
        mock_context = AgentContext(
            trace_id="trace_123",
            session_id="session_123",
            created_at=None,
            metadata={}
        )
        
        mock_analysis_result = AgentResult(
            agent_type=AgentType.ANALYSIS,
            status="completed",
            output={"batch_score": 0.75},
            execution_time=1.5,
            error_message=None
        )
        
        mock_execution = Mock(spec=PipelineExecution)
        mock_execution.context = mock_context
        mock_execution.get_agent_result.side_effect = lambda agent_type: {
            AgentType.ANALYSIS: mock_analysis_result,
            AgentType.DECISION: None
        }.get(agent_type)
        
        self.mock_orchestrator.execute_pipeline.return_value = mock_execution
        
        # Act
        result = self.use_case.execute(request)
        
        # Assert
        assert result.trace_id == "trace_123"
        assert result.score == 0.75
        assert result.decision == {}
        assert result.batch_size == 1
    
    def test_create_pipeline_config(self):
        """Test que se crea la configuración correcta del pipeline."""
        # Act
        config = self.use_case._create_pipeline_config()
        
        # Assert
        assert config.pipeline_type.value == "threat_detection"
        assert AgentType.INGESTION in config.agent_sequence
        assert AgentType.ANALYSIS in config.agent_sequence
        assert AgentType.DECISION in config.agent_sequence
        assert config.timeout_seconds == 300
        assert config.retry_attempts == 3
        assert config.parallel_execution is False
        assert config.fail_fast is True
        assert "description" in config.metadata
        assert "version" in config.metadata
