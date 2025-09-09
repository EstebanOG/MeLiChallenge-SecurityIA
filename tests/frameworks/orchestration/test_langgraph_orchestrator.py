"""
Tests para el orquestador LangGraph.
"""

import pytest
from unittest.mock import Mock, patch
from src.frameworks.orchestration.langgraph_orchestrator import LangGraphPipelineOrchestrator
from src.domain.entities.agent import AgentContext
from src.domain.entities.pipeline import PipelineExecution, PipelineConfig, PipelineState


class TestLangGraphPipelineOrchestrator:
    """Tests para LangGraphPipelineOrchestrator."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.orchestrator = LangGraphPipelineOrchestrator()
        self.sample_logs = [
            {
                "session_id": "session_001",
                "network_packet_size": 150,
                "protocol_type": "TCP",
                "login_attempts": 5,
                "session_duration": 250.0,
                "encryption_used": "AES",
                "ip_reputation_score": 0.8,
                "failed_logins": 2,
                "browser_type": "Chrome",
                "unusual_time_access": 0,
                "attack_detected": 0
            }
        ]
    
    def test_init(self):
        """Test de inicialización del orquestador."""
        assert self.orchestrator.graph_builder is not None
        assert self.orchestrator.pipeline_executor is not None
        assert self.orchestrator._graph is None
    
    def test_graph_lazy_loading(self):
        """Test del lazy loading del grafo."""
        with patch.object(self.orchestrator.graph_builder, 'build_graph') as mock_build:
            mock_graph = Mock()
            mock_build.return_value = mock_graph
            
            # Primera llamada debe construir el grafo
            graph1 = self.orchestrator.graph
            assert graph1 == mock_graph
            mock_build.assert_called_once()
            
            # Segunda llamada debe usar el grafo cacheado
            graph2 = self.orchestrator.graph
            assert graph2 == mock_graph
            assert mock_build.call_count == 1
    
    def test_execute_pipeline_success(self):
        """Test de ejecución exitosa del pipeline."""
        mock_graph = Mock()
        mock_execution = Mock(spec=PipelineExecution)
        mock_context = Mock(spec=AgentContext)
        
        # Mock del atributo privado _graph
        self.orchestrator._graph = mock_graph
        with patch.object(self.orchestrator.pipeline_executor, 'execute_pipeline') as mock_execute:
            mock_execute.return_value = mock_execution
            
            result = self.orchestrator.execute_pipeline(
                logs=self.sample_logs,
                context=mock_context
            )
            
            mock_execute.assert_called_once_with(
                graph=mock_graph,
                logs=self.sample_logs,
                context=mock_context
            )
            assert result == mock_execution
    
    def test_execute_pipeline_without_context(self):
        """Test de ejecución del pipeline sin contexto."""
        mock_graph = Mock()
        mock_execution = Mock(spec=PipelineExecution)
        
        # Mock del atributo privado _graph
        self.orchestrator._graph = mock_graph
        with patch.object(self.orchestrator.pipeline_executor, 'execute_pipeline') as mock_execute:
            mock_execute.return_value = mock_execution
            
            result = self.orchestrator.execute_pipeline(logs=self.sample_logs)
            
            mock_execute.assert_called_once_with(
                graph=mock_graph,
                logs=self.sample_logs,
                context=None
            )
            assert result == mock_execution
    
    def test_execute_step_not_implemented(self):
        """Test de que execute_step no está implementado."""
        mock_state = Mock(spec=PipelineState)
        
        with pytest.raises(NotImplementedError) as exc_info:
            self.orchestrator.execute_step(mock_state, "test_agent")
        
        assert "LangGraph maneja la ejecución completa del pipeline" in str(exc_info.value)
    
    def test_get_pipeline_status_not_implemented(self):
        """Test de que get_pipeline_status no está implementado."""
        with pytest.raises(NotImplementedError) as exc_info:
            self.orchestrator.get_pipeline_status("test_execution_id")
        
        assert "LangGraph ejecuta pipelines de forma síncrona" in str(exc_info.value)
    
    def test_validate_pipeline_config(self):
        """Test de validación de configuración del pipeline."""
        mock_config = Mock(spec=PipelineConfig)
        
        # Para LangGraph, la configuración siempre es válida
        errors = self.orchestrator.validate_pipeline_config(mock_config)
        assert errors == []
    
    def test_execute_pipeline_with_empty_logs(self):
        """Test de ejecución con logs vacíos."""
        mock_graph = Mock()
        mock_execution = Mock(spec=PipelineExecution)
        
        # Mock del atributo privado _graph
        self.orchestrator._graph = mock_graph
        with patch.object(self.orchestrator.pipeline_executor, 'execute_pipeline') as mock_execute:
            mock_execute.return_value = mock_execution
            
            result = self.orchestrator.execute_pipeline(logs=[])
            
            mock_execute.assert_called_once_with(
                graph=mock_graph,
                logs=[],
                context=None
            )
            assert result == mock_execution


class TestLangGraphPipelineOrchestratorIntegration:
    """Tests de integración para LangGraphPipelineOrchestrator."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.orchestrator = LangGraphPipelineOrchestrator()
        self.sample_logs = [
            {
                "session_id": "session_001",
                "network_packet_size": 150,
                "protocol_type": "TCP",
                "login_attempts": 5,
                "session_duration": 250.0,
                "encryption_used": "AES",
                "ip_reputation_score": 0.8,
                "failed_logins": 2,
                "browser_type": "Chrome",
                "unusual_time_access": 0,
                "attack_detected": 0
            }
        ]
    
    @pytest.mark.integration
    def test_full_pipeline_execution(self):
        """Test de ejecución completa del pipeline con mocks realistas."""
        mock_graph = Mock()
        mock_execution_result = {
            "trace_id": "test-trace-123",
            "score": 0.75,
            "decision": {
                "action": "alert",
                "confidence": 0.85,
                "threat_detected": True,
                "anomaly_detected": True,
                "reasoning": "Anomaly detected with high confidence"
            },
            "batch_size": 1
        }
        
        with patch.object(self.orchestrator.graph_builder, 'build_graph') as mock_build:
            with patch.object(self.orchestrator.pipeline_executor, 'execute_pipeline') as mock_execute:
                mock_build.return_value = mock_graph
                mock_execute.return_value = mock_execution_result
                
                result = self.orchestrator.execute_pipeline(logs=self.sample_logs)
                
                mock_execute.assert_called_once()
                assert result["trace_id"] == "test-trace-123"
                assert result["score"] == 0.75
                assert result["decision"]["threat_detected"] is True
                assert result["batch_size"] == 1
    
    @pytest.mark.integration
    def test_pipeline_error_handling(self):
        """Test del manejo de errores en el pipeline."""
        mock_graph = Mock()
        
        with patch.object(self.orchestrator.graph_builder, 'build_graph') as mock_build:
            with patch.object(self.orchestrator.pipeline_executor, 'execute_pipeline') as mock_execute:
                mock_build.return_value = mock_graph
                mock_execute.side_effect = Exception("Pipeline execution failed")
                
                with pytest.raises(Exception) as exc_info:
                    self.orchestrator.execute_pipeline(logs=self.sample_logs)
                
                assert "Pipeline execution failed" in str(exc_info.value)


class TestLangGraphPipelineOrchestratorEdgeCases:
    """Tests para casos edge del orquestador LangGraph."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.orchestrator = LangGraphPipelineOrchestrator()
    
    def test_graph_builder_error(self):
        """Test de error en la construcción del grafo."""
        with patch.object(self.orchestrator.graph_builder, 'build_graph') as mock_build:
            mock_build.side_effect = Exception("Graph construction failed")
            
            with pytest.raises(Exception) as exc_info:
                _ = self.orchestrator.graph
            
            assert "Graph construction failed" in str(exc_info.value)
    
    def test_pipeline_executor_error(self):
        """Test de error en el ejecutor del pipeline."""
        mock_graph = Mock()
        sample_logs = [{"session_id": "test"}]
        
        # Mock del atributo privado _graph
        self.orchestrator._graph = mock_graph
        with patch.object(self.orchestrator.pipeline_executor, 'execute_pipeline') as mock_execute:
            mock_execute.side_effect = Exception("Execution failed")
            
            with pytest.raises(Exception) as exc_info:
                self.orchestrator.execute_pipeline(logs=sample_logs)
                
                assert "Execution failed" in str(exc_info.value)
    
    def test_none_logs(self):
        """Test con logs None."""
        mock_graph = Mock()
        
        # Mock del atributo privado _graph
        self.orchestrator._graph = mock_graph
        with patch.object(self.orchestrator.pipeline_executor, 'execute_pipeline') as mock_execute:
            mock_execute.return_value = {}
            
            # Debe manejar logs None sin fallar
            result = self.orchestrator.execute_pipeline(logs=None)
            
            mock_execute.assert_called_once_with(
                graph=mock_graph,
                logs=None,
                context=None
            )
            assert result == {}
