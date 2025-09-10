"""
Tests End-to-End para el flujo completo de LangGraph.

Estos tests prueban el pipeline completo de detección de amenazas
usando datos reales del dataset, sin mocks.
"""

import pytest
import pandas as pd
import os
from pathlib import Path
from src.frameworks.orchestration.langgraph_orchestrator import LangGraphPipelineOrchestrator


class TestLangGraphE2E:
    """Tests End-to-End para el flujo completo de LangGraph."""
    
    @pytest.fixture
    def orchestrator(self):
        """Fixture para el orquestador LangGraph."""
        from src.adapters.ml.supervised_threat_detector_adapter import SupervisedThreatDetectorAdapter
        threat_detector = SupervisedThreatDetectorAdapter()
        return LangGraphPipelineOrchestrator(threat_detector)
    
    @pytest.fixture
    def sample_logs_attack(self):
        """Fixture con logs de ataque para testing."""
        return {
            "session_id": "SID_E2E_ATTACK_001",
            "network_packet_size": 800,
            "protocol_type": "TCP",
            "login_attempts": 5,
            "session_duration": 1200.0,
            "encryption_used": "DES",
            "ip_reputation_score": 0.2,
            "failed_logins": 4,
            "browser_type": "Chrome",
            "unusual_time_access": 1,
            "attack_detected": 1,
            "failed_auth_attempts": 4,
            "cpu_usage": 95.0,
            "memory_usage": 85.0,
            "network_in_kb": 800,
            "avg_response_time_ms": 600.0,
            "is_encrypted": 0
        }
    
    @pytest.fixture
    def sample_logs_normal(self):
        """Fixture con logs normales para testing."""
        return {
            "session_id": "SID_E2E_NORMAL_001",
            "network_packet_size": 400,
            "protocol_type": "TCP",
            "login_attempts": 2,
            "session_duration": 300.0,
            "encryption_used": "AES",
            "ip_reputation_score": 0.8,
            "failed_logins": 0,
            "browser_type": "Firefox",
            "unusual_time_access": 0,
            "attack_detected": 0,
            "failed_auth_attempts": 0,
            "cpu_usage": 35.0,
            "memory_usage": 45.0,
            "network_in_kb": 400,
            "avg_response_time_ms": 200.0,
            "is_encrypted": 1
        }
    
    @pytest.fixture
    def real_dataset_logs(self):
        """Fixture que carga logs reales del dataset si está disponible."""
        dataset_path = Path("notebooks/data/processed/dataset_complete.csv")
        
        if not dataset_path.exists():
            pytest.skip("Dataset real no encontrado, usando datos simulados")
        
        try:
            df = pd.read_csv(dataset_path)
            
            # Seleccionar muestras del dataset real
            attack_samples = df[df['attack_detected'] == 1].sample(1)
            normal_samples = df[df['attack_detected'] == 0].sample(1)
            
            test_logs = []
            
            # Convertir muestras de ataque
            for _, row in attack_samples.iterrows():
                test_logs.append({
                    "session_id": row['session_id'],
                    "network_packet_size": row['network_packet_size'],
                    "protocol_type": row['protocol_type'],
                    "login_attempts": row['login_attempts'],
                    "session_duration": row['session_duration'],
                    "encryption_used": row['encryption_used'],
                    "ip_reputation_score": row['ip_reputation_score'],
                    "failed_logins": row['failed_logins'],
                    "browser_type": row['browser_type'],
                    "unusual_time_access": row['unusual_time_access'],
                    "attack_detected": row['attack_detected'],
                    "failed_auth_attempts": row['failed_logins'],
                    "cpu_usage": min(95, 20 + (row['network_packet_size'] / 10)),
                    "memory_usage": min(90, 30 + (row['session_duration'] / 20)),
                    "network_in_kb": row['network_packet_size'],
                    "avg_response_time_ms": row['session_duration'] * 2,
                    "is_encrypted": 1 if row['encryption_used'] == 'AES' else 0
                })
            
            # Convertir muestras normales
            for _, row in normal_samples.iterrows():
                test_logs.append({
                    "session_id": row['session_id'],
                    "network_packet_size": row['network_packet_size'],
                    "protocol_type": row['protocol_type'],
                    "login_attempts": row['login_attempts'],
                    "session_duration": row['session_duration'],
                    "encryption_used": row['encryption_used'],
                    "ip_reputation_score": row['ip_reputation_score'],
                    "failed_logins": row['failed_logins'],
                    "browser_type": row['browser_type'],
                    "unusual_time_access": row['unusual_time_access'],
                    "attack_detected": row['attack_detected'],
                    "failed_auth_attempts": row['failed_logins'],
                    "cpu_usage": min(60, 20 + (row['network_packet_size'] / 15)),
                    "memory_usage": min(70, 30 + (row['session_duration'] / 30)),
                    "network_in_kb": row['network_packet_size'],
                    "avg_response_time_ms": row['session_duration'] * 1.5,
                    "is_encrypted": 1 if row['encryption_used'] == 'AES' else 0
                })
            
            return test_logs
            
        except Exception as e:
            pytest.skip(f"Error cargando dataset real: {e}")
    
    @pytest.mark.e2e
    def test_orchestrator_initialization(self, orchestrator):
        """Test de inicialización del orquestador."""
        assert orchestrator is not None
        assert orchestrator.graph_builder is not None
        assert orchestrator.pipeline_executor is not None
        assert orchestrator._graph is None  # Lazy loading
    
    @pytest.mark.e2e
    def test_graph_lazy_loading(self, orchestrator):
        """Test del lazy loading del grafo."""
        # Primera vez debe construir el grafo
        graph1 = orchestrator.graph
        assert graph1 is not None
        
        # Segunda vez debe usar el cache
        graph2 = orchestrator.graph
        assert graph2 is graph1  # Mismo objeto
    
    @pytest.mark.e2e
    def test_pipeline_execution_with_simulated_data(self, orchestrator, sample_logs_attack, sample_logs_normal):
        """Test de ejecución del pipeline con datos simulados."""
        test_logs = [sample_logs_attack, sample_logs_normal]
        
        # Ejecutar pipeline
        result = orchestrator.execute_pipeline(test_logs)
        
        # Validaciones básicas
        assert result is not None
        assert hasattr(result, 'execution_id')
        assert hasattr(result, 'status')
        assert hasattr(result, 'total_execution_time_ms')
        assert hasattr(result, 'agent_results')
        
        # Validar que se ejecutaron agentes
        assert len(result.agent_results) > 0
        
        # Validar que el tiempo de ejecución es razonable
        assert result.total_execution_time_ms > 0
        assert result.total_execution_time_ms < 30000  # Menos de 30 segundos
    
    @pytest.mark.e2e
    @pytest.mark.slow
    def test_pipeline_execution_with_real_data(self, orchestrator, real_dataset_logs):
        """Test de ejecución del pipeline con datos reales del dataset."""
        test_logs = real_dataset_logs
        
        # Ejecutar pipeline
        result = orchestrator.execute_pipeline(test_logs)
        
        # Validaciones básicas
        assert result is not None
        assert hasattr(result, 'execution_id')
        assert hasattr(result, 'status')
        assert hasattr(result, 'total_execution_time_ms')
        assert hasattr(result, 'agent_results')
        
        # Validar que se ejecutaron agentes
        assert len(result.agent_results) > 0
        
        # Validar que el tiempo de ejecución es razonable
        assert result.total_execution_time_ms > 0
        assert result.total_execution_time_ms < 60000  # Menos de 1 minuto
        
        # Validar que hay al menos un log de ataque y uno normal
        assert len(test_logs) >= 2
        attack_logs = [log for log in test_logs if log.get('attack_detected', 0) == 1]
        normal_logs = [log for log in test_logs if log.get('attack_detected', 0) == 0]
        assert len(attack_logs) > 0
        assert len(normal_logs) > 0
    
    @pytest.mark.e2e
    def test_pipeline_execution_with_empty_logs(self, orchestrator):
        """Test de ejecución del pipeline con logs vacíos."""
        result = orchestrator.execute_pipeline([])
        
        # Debe manejar logs vacíos sin fallar
        assert result is not None
        assert hasattr(result, 'execution_id')
        assert hasattr(result, 'status')
    
    @pytest.mark.e2e
    def test_pipeline_execution_with_single_log(self, orchestrator, sample_logs_attack):
        """Test de ejecución del pipeline con un solo log."""
        result = orchestrator.execute_pipeline([sample_logs_attack])
        
        # Validaciones básicas
        assert result is not None
        assert hasattr(result, 'execution_id')
        assert hasattr(result, 'status')
        assert hasattr(result, 'agent_results')
        
        # Debe ejecutar al menos un agente
        assert len(result.agent_results) > 0
    
    @pytest.mark.e2e
    def test_agent_results_structure(self, orchestrator, sample_logs_attack, sample_logs_normal):
        """Test de la estructura de resultados de agentes."""
        test_logs = [sample_logs_attack, sample_logs_normal]
        result = orchestrator.execute_pipeline(test_logs)
        
        # Validar estructura de agent_results
        for agent_result in result.agent_results:
            assert hasattr(agent_result, 'agent_type')
            assert hasattr(agent_result, 'status')
            assert hasattr(agent_result, 'execution_time_ms')
            assert hasattr(agent_result, 'output')
            
            # Validar que el tiempo de ejecución es razonable
            assert agent_result.execution_time_ms >= 0
            assert agent_result.execution_time_ms < 10000  # Menos de 10 segundos por agente
    
    @pytest.mark.e2e
    @pytest.mark.slow
    def test_pipeline_performance(self, orchestrator, real_dataset_logs):
        """Test de rendimiento del pipeline con datos reales."""
        import time
        
        start_time = time.time()
        result = orchestrator.execute_pipeline(real_dataset_logs)
        end_time = time.time()
        
        execution_time = (end_time - start_time) * 1000  # Convertir a ms
        
        # Validar que el pipeline es eficiente
        assert execution_time < 30000  # Menos de 30 segundos
        assert result.total_execution_time_ms < 30000
        
        # El tiempo reportado debe ser similar al medido
        assert abs(result.total_execution_time_ms - execution_time) < 5000  # Tolerancia de 5 segundos
