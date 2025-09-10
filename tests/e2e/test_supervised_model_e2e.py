"""
Tests End-to-End para el modelo supervisado.

Prueba el flujo completo de entrenamiento y análisis usando
el modelo supervisado de detección de amenazas.
"""

import pytest
import os
import sys
from unittest.mock import patch, mock_open, Mock
import json

# Agregar src al path
sys.path.append('src')

from src.adapters.ml.supervised_model_adapter import SupervisedModelAdapter
from src.adapters.ml.supervised_threat_detector_adapter import SupervisedThreatDetectorAdapter
from src.frameworks.orchestration.agents.supervised_agent import SupervisedAgent
from src.application.use_cases.train_supervised_model import TrainSupervisedModelUseCase
from src.adapters.controllers.supervised_model_controller import SupervisedModelController
from src.frameworks.orchestration.langgraph_orchestrator import LangGraphPipelineOrchestrator
from src.application.use_cases.analyze_logs import AnalyzeThreatLogsUseCase
from src.domain.entities.dto import ThreatAnalyzeRequestDTO
from src.domain.entities.agent import AgentType


class TestSupervisedModelE2E:
    """Tests End-to-End para el modelo supervisado."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        # Crear adaptadores
        self.supervised_model_adapter = SupervisedModelAdapter("test_models/supervised_model.joblib")
        self.threat_detector_adapter = SupervisedThreatDetectorAdapter("test_models/supervised_model.joblib")
        
        # Crear caso de uso de entrenamiento
        self.train_use_case = TrainSupervisedModelUseCase(self.supervised_model_adapter)
        
        # Crear controlador
        self.controller = SupervisedModelController(self.train_use_case)
        
        # Crear orquestador
        self.orchestrator = LangGraphPipelineOrchestrator(self.threat_detector_adapter)
        
        # Crear caso de uso de análisis
        self.analyze_use_case = AnalyzeThreatLogsUseCase(self.orchestrator, self.supervised_model_adapter)
    
    @patch('os.path.exists')
    @patch('src.frameworks.ml.supervised_model.SupervisedThreatDetector.train')
    @patch('src.frameworks.ml.supervised_model.SupervisedThreatDetector.get_feature_importance')
    def test_complete_training_and_analysis_flow(self, mock_feature_importance, mock_train, mock_exists):
        """Test del flujo completo de entrenamiento y análisis."""
        # Configurar mocks
        mock_exists.return_value = True  # Dataset existe
        mock_train.return_value = {
            'auc_score': 0.8789,
            'precision': 0.8234,
            'recall': 0.8012,
            'f1_score': 0.8121,
            'train_samples': 7629,
            'test_samples': 1908
        }
        mock_feature_importance.return_value = {
            'failed_logins': 0.25,
            'ip_reputation_score': 0.20,
            'login_attempts': 0.15
        }
        
        # 1. Entrenar el modelo
        print("1️⃣ Entrenando modelo supervisado...")
        train_result = self.train_use_case.execute()
        
        # Verificar entrenamiento
        assert train_result.success == True
        assert "Modelo supervisado entrenado exitosamente" in train_result.message
        # Verificar métricas en rangos razonables
        assert 0.85 <= train_result.metrics['auc_score'] <= 0.95, f"AUC score {train_result.metrics['auc_score']} fuera del rango"
        assert 0.80 <= train_result.metrics['precision'] <= 0.90, f"Precision {train_result.metrics['precision']} fuera del rango"
        print(f"   ✅ Modelo entrenado - AUC: {train_result.metrics['auc_score']}")
        
        # 2. Verificar estado del modelo
        print("2️⃣ Verificando estado del modelo...")
        model_status = self.train_use_case.get_model_status()
        
        # Verificar estado
        assert model_status['is_trained'] == True
        assert model_status['model_exists'] == True
        # Verificar que el AUC score esté en un rango razonable (0.85-0.95)
        auc_score = model_status['metrics']['auc_score']
        assert 0.85 <= auc_score <= 0.95, f"AUC score {auc_score} fuera del rango esperado"
        print(f"   ✅ Estado verificado - Entrenado: {model_status['is_trained']}, AUC: {auc_score:.4f}")
        
        # 3. Crear agente supervisado
        print("3️⃣ Creando agente supervisado...")
        agent = SupervisedAgent(self.threat_detector_adapter)
        
        # Verificar agente
        assert agent.name == "supervised_agent"
        assert agent.threat_detector == self.threat_detector_adapter
        print("   ✅ Agente creado correctamente")
        
        # 4. Probar análisis de logs (mock del orquestador)
        print("4️⃣ Probando análisis de logs...")
        
        # Mock del orquestador para el análisis
        with patch.object(self.orchestrator, 'execute_pipeline') as mock_execute:
            # Crear mocks de los resultados de agentes
            mock_supervised_result = Mock()
            mock_supervised_result.output = {
                "decision": "attack_known",
                "confidence": 0.85,
                "threat_level": "high",
                "reasoning": "Ataque detectado por modelo supervisado"
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
                "reasoning": "Ataque confirmado"
            }
            
            mock_report_result = Mock()
            mock_report_result.output = {
                "message": "Análisis completado"
            }
            
            # Crear mock del resultado de ejecución
            mock_execution_result = Mock()
            mock_execution_result.get_agent_result.side_effect = lambda agent_type: {
                AgentType.INGESTION: mock_supervised_result,
                AgentType.ANALYSIS: mock_unsupervised_result,
                AgentType.DECISION: mock_decision_result,
                AgentType.NOTIFICATION: mock_report_result
            }.get(agent_type)
            mock_execution_result.context.trace_id = "test_exec_123"
            
            mock_execute.return_value = mock_execution_result
            
            # Crear request de análisis
            request = ThreatAnalyzeRequestDTO(
                logs=[
                    {
                        'session_id': 'attack_001',
                        'network_packet_size': 800,
                        'protocol_type': 'TCP',
                        'login_attempts': 5,
                        'session_duration': 2000.0,
                        'encryption_used': 'DES',
                        'ip_reputation_score': 0.1,
                        'failed_logins': 5,
                        'browser_type': 'Chrome',
                        'unusual_time_access': 1
                    }
                ]
            )
            
            # Ejecutar análisis
            analysis_result = self.analyze_use_case.execute(request)
            
            # Verificar análisis
            assert analysis_result.trace_id == "test_exec_123"
            assert analysis_result.score == 0.8  # threat_detected = True
            assert analysis_result.decision["action"] == "block"
            assert 0.80 <= analysis_result.decision["confidence"] <= 0.90, f"Confidence {analysis_result.decision['confidence']} fuera del rango"
            assert analysis_result.decision["threat_detected"] == True
            assert analysis_result.batch_size == 1
            print(f"   ✅ Análisis completado - Decisión: {analysis_result.decision['action']}")
    
    def test_agent_with_different_log_types(self):
        """Test del agente con diferentes tipos de logs."""
        # Crear agente
        agent = SupervisedAgent(self.threat_detector_adapter)
        
        # Mock del detector
        with patch.object(self.threat_detector_adapter, 'is_ready', return_value=True), \
             patch.object(self.threat_detector_adapter, 'predict') as mock_predict:
            
            # Test 1: Logs de ataque obvio
            print("🔍 Probando logs de ataque obvio...")
            mock_predict.return_value = {
                'is_attack': True,
                'confidence': 0.95,
                'probability': 0.92,
                'reasoning': 'Múltiples indicadores de ataque detectados'
            }
            
            attack_logs = [
                {
                    'session_id': 'attack_001',
                    'network_packet_size': 1200,
                    'protocol_type': 'UDP',
                    'login_attempts': 8,
                    'session_duration': 3000.0,
                    'encryption_used': 'DES',
                    'ip_reputation_score': 0.05,
                    'failed_logins': 8,
                    'browser_type': 'Firefox',
                    'unusual_time_access': 1
                }
            ]
            
            state = {
                'logs': attack_logs,
                'agent_results': {},
                'execution_path': []
            }
            
            result_state = agent.execute(state)
            result = result_state['agent_results']['supervised_agent']
            
            assert result['decision'] == 'attack_known'
            assert result['threat_level'] == 'high'
            assert result['next_agent'] == 'decision_agent'
            print(f"   ✅ Ataque detectado - Confianza: {result['confidence']}")
            
            # Test 2: Logs de comportamiento normal
            print("🔍 Probando logs de comportamiento normal...")
            mock_predict.return_value = {
                'is_attack': False,
                'confidence': 0.90,
                'probability': 0.15,
                'reasoning': 'Comportamiento normal detectado'
            }
            
            normal_logs = [
                {
                    'session_id': 'normal_001',
                    'failed_logins': 1,
                    'ip_reputation_score': 0.8,
                    'unusual_time_access': 0,
                    'encryption_used': 'AES',
                    'session_duration': 300,
                    'network_packet_size': 400
                }
            ]
            
            state = {
                'logs': normal_logs,
                'agent_results': {},
                'execution_path': []
            }
            
            result_state = agent.execute(state)
            result = result_state['agent_results']['supervised_agent']
            
            assert result['decision'] == 'normal'
            assert result['threat_level'] == 'low'
            assert result['next_agent'] == 'unsupervised_agent'
            print(f"   ✅ Comportamiento normal - Confianza: {result['confidence']}")
    
    def test_error_handling_flow(self):
        """Test del manejo de errores en el flujo completo."""
        print("🔍 Probando manejo de errores...")
        
        # Test 1: Modelo no entrenado
        print("   - Modelo no entrenado...")
        with patch.object(self.supervised_model_adapter, 'is_trained', return_value=False):
            with pytest.raises(ValueError, match="El modelo supervisado no está entrenado"):
                request = ThreatAnalyzeRequestDTO(logs=[{
                    'session_id': 'test',
                    'network_packet_size': 500,
                    'protocol_type': 'TCP',
                    'login_attempts': 3,
                    'session_duration': 300.0,
                    'encryption_used': 'AES',
                    'ip_reputation_score': 0.2,
                    'failed_logins': 3,
                    'browser_type': 'Chrome',
                    'unusual_time_access': 0
                }])
                self.analyze_use_case.execute(request)
        print("   ✅ Error de modelo no entrenado manejado correctamente")
        
        # Test 2: Detector no listo
        print("   - Detector no listo...")
        agent = SupervisedAgent(self.threat_detector_adapter)
        with patch.object(self.threat_detector_adapter, 'is_ready', return_value=False):
            with pytest.raises(ValueError, match="El modelo ML no está entrenado"):
                state = {'logs': [{
                    'session_id': 'test',
                    'network_packet_size': 500,
                    'protocol_type': 'TCP',
                    'login_attempts': 3,
                    'session_duration': 300.0,
                    'encryption_used': 'AES',
                    'ip_reputation_score': 0.2,
                    'failed_logins': 3,
                    'browser_type': 'Chrome',
                    'unusual_time_access': 0
                }], 'agent_results': {}, 'execution_path': []}
                agent.execute(state)
        print("   ✅ Error de detector no listo manejado correctamente")
        
        # Test 3: Error en predicción
        print("   - Error en predicción...")
        with patch.object(self.threat_detector_adapter, 'is_ready', return_value=True), \
             patch.object(self.threat_detector_adapter, 'predict', side_effect=Exception("Error en predicción")):
            with pytest.raises(Exception, match="Error en predicción"):
                state = {'logs': [{
                    'session_id': 'test',
                    'network_packet_size': 500,
                    'protocol_type': 'TCP',
                    'login_attempts': 3,
                    'session_duration': 300.0,
                    'encryption_used': 'AES',
                    'ip_reputation_score': 0.2,
                    'failed_logins': 3,
                    'browser_type': 'Chrome',
                    'unusual_time_access': 0
                }], 'agent_results': {}, 'execution_path': []}
                agent.execute(state)
        print("   ✅ Error en predicción manejado correctamente")
    
    def test_performance_metrics(self):
        """Test de métricas de rendimiento."""
        print("🔍 Probando métricas de rendimiento...")
        
        # Mock de métricas de entrenamiento
        with patch('os.path.exists', return_value=True), \
             patch('src.frameworks.ml.supervised_model.SupervisedThreatDetector.train') as mock_train, \
             patch('src.frameworks.ml.supervised_model.SupervisedThreatDetector.get_feature_importance') as mock_feature:
            
            mock_train.return_value = {
                'auc_score': 0.8789,
                'precision': 0.8234,
                'recall': 0.8012,
                'f1_score': 0.8121,
                'train_samples': 7629,
                'test_samples': 1908
            }
            mock_feature.return_value = {
                'failed_logins': 0.25,
                'ip_reputation_score': 0.20,
                'login_attempts': 0.15
            }
            
            # Entrenar modelo
            result = self.train_use_case.execute()
            
            # Verificar métricas
            assert result.metrics['auc_score'] >= 0.8  # AUC mínimo aceptable
            assert result.metrics['precision'] >= 0.8  # Precisión mínima aceptable
            assert result.metrics['recall'] >= 0.8     # Recall mínimo aceptable
            assert result.metrics['f1_score'] >= 0.8   # F1 mínimo aceptable
            
            print(f"   ✅ Métricas de rendimiento:")
            print(f"      - AUC: {result.metrics['auc_score']:.4f}")
            print(f"      - Precisión: {result.metrics['precision']:.4f}")
            print(f"      - Recall: {result.metrics['recall']:.4f}")
            print(f"      - F1-Score: {result.metrics['f1_score']:.4f}")
    
    def test_feature_importance_analysis(self):
        """Test de análisis de importancia de características."""
        print("🔍 Probando análisis de importancia de características...")
        
        # Mock de importancia de características
        with patch('os.path.exists', return_value=True), \
             patch('src.frameworks.ml.supervised_model.SupervisedThreatDetector.train') as mock_train, \
             patch('src.frameworks.ml.supervised_model.SupervisedThreatDetector.get_feature_importance') as mock_feature:
            
            mock_train.return_value = {
                'auc_score': 0.85,
                'precision': 0.80,
                'recall': 0.75,
                'f1_score': 0.77,
                'train_samples': 1000,
                'test_samples': 200
            }
            
            # Importancia de características simulada
            feature_importance = {
                'failed_logins': 0.30,
                'ip_reputation_score': 0.25,
                'login_attempts': 0.20,
                'unusual_time_access': 0.15,
                'session_duration': 0.10
            }
            mock_feature.return_value = feature_importance
            
            # Entrenar modelo
            result = self.train_use_case.execute()
            
            # Verificar importancia de características
            assert 'failed_logins' in result.metrics['feature_importance']
            assert 'ip_reputation_score' in result.metrics['feature_importance']
            # Verificar importancia de características en rangos razonables
            failed_logins_importance = result.metrics['feature_importance']['failed_logins']
            ip_rep_importance = result.metrics['feature_importance']['ip_reputation_score']
            assert 0.20 <= failed_logins_importance <= 0.40, f"Failed logins importance {failed_logins_importance} fuera del rango"
            assert 0.15 <= ip_rep_importance <= 0.35, f"IP reputation importance {ip_rep_importance} fuera del rango"
            
            print("   ✅ Importancia de características:")
            for feature, importance in result.metrics['feature_importance'].items():
                print(f"      - {feature}: {importance:.3f}")
