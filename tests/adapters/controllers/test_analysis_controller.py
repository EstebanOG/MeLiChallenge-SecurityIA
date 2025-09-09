"""
Tests para el controlador de análisis.
"""

import pytest
from unittest.mock import Mock, patch
from fastapi import HTTPException
from src.adapters.controllers.analysis_controller import AnalysisController
from src.domain.entities.dto import ThreatAnalyzeRequestDTO, ThreatAnalyzeResponseDTO
from src.application.use_cases.analyze_logs import AnalyzeThreatLogsUseCase


class TestAnalysisController:
    """Tests para AnalysisController."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.mock_use_case = Mock(spec=AnalyzeThreatLogsUseCase)
        self.controller = AnalysisController(self.mock_use_case)
        self.sample_request = ThreatAnalyzeRequestDTO(
            logs=[
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
        )
    
    def test_init(self):
        """Test de inicialización del controlador."""
        assert self.controller.analyze_use_case == self.mock_use_case
        assert self.controller.router is not None
    
    def test_analyze_threat_batch_success(self):
        """Test de análisis exitoso de amenazas."""
        expected_response = ThreatAnalyzeResponseDTO(
            trace_id="test-trace-123",
            score=0.75,
            decision={
                "action": "alert",
                "confidence": 0.85,
                "threat_detected": True,
                "anomaly_detected": True,
                "reasoning": "Anomaly detected with high confidence"
            },
            batch_size=1
        )
        
        self.mock_use_case.execute.return_value = expected_response
        
        # Obtener la función del endpoint
        endpoint_func = self.controller.router.routes[0].endpoint
        
        result = endpoint_func(self.sample_request)
        
        self.mock_use_case.execute.assert_called_once_with(self.sample_request)
        assert result == expected_response
    
    def test_analyze_threat_batch_with_multiple_logs(self):
        """Test de análisis con múltiples logs."""
        multiple_logs_request = ThreatAnalyzeRequestDTO(
            logs=[
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
                },
                {
                    "session_id": "session_002",
                    "network_packet_size": 500,
                    "protocol_type": "UDP",
                    "login_attempts": 10,
                    "session_duration": 100.0,
                    "encryption_used": "DES",
                    "ip_reputation_score": 0.3,
                    "failed_logins": 5,
                    "browser_type": "Firefox",
                    "unusual_time_access": 1,
                    "attack_detected": 1
                }
            ]
        )
        
        expected_response = ThreatAnalyzeResponseDTO(
            trace_id="test-trace-multi",
            score=0.65,
            decision={
                "action": "monitor",
                "confidence": 0.70,
                "threat_detected": False,
                "anomaly_detected": False,
                "reasoning": "Mixed behavior detected, monitoring recommended"
            },
            batch_size=2
        )
        
        self.mock_use_case.execute.return_value = expected_response
        
        endpoint_func = self.controller.router.routes[0].endpoint
        result = endpoint_func(multiple_logs_request)
        
        self.mock_use_case.execute.assert_called_once_with(multiple_logs_request)
        assert result == expected_response
        assert result.batch_size == 2
    
    def test_analyze_threat_batch_use_case_error(self):
        """Test de manejo de errores del caso de uso."""
        error_message = "Pipeline execution failed"
        self.mock_use_case.execute.side_effect = Exception(error_message)
        
        endpoint_func = self.controller.router.routes[0].endpoint
        
        with pytest.raises(HTTPException) as exc_info:
            endpoint_func(self.sample_request)
        
        assert exc_info.value.status_code == 500
        assert f"Error en análisis: {error_message}" in str(exc_info.value.detail)
        self.mock_use_case.execute.assert_called_once_with(self.sample_request)
    
    def test_analyze_threat_batch_validation_error(self):
        """Test de manejo de errores de validación."""
        validation_error = ValueError("Invalid log format")
        self.mock_use_case.execute.side_effect = validation_error
        
        endpoint_func = self.controller.router.routes[0].endpoint
        
        with pytest.raises(HTTPException) as exc_info:
            endpoint_func(self.sample_request)
        
        assert exc_info.value.status_code == 500
        assert "Error en análisis: Invalid log format" in str(exc_info.value.detail)
    
    def test_analyze_threat_batch_empty_logs(self):
        """Test de análisis con logs vacíos."""
        empty_request = ThreatAnalyzeRequestDTO(logs=[])
        
        expected_response = ThreatAnalyzeResponseDTO(
            trace_id="test-trace-empty",
            score=0.0,
            decision={
                "action": "monitor",
                "confidence": 1.0,
                "threat_detected": False,
                "anomaly_detected": False,
                "reasoning": "No logs to analyze"
            },
            batch_size=0
        )
        
        self.mock_use_case.execute.return_value = expected_response
        
        endpoint_func = self.controller.router.routes[0].endpoint
        result = endpoint_func(empty_request)
        
        self.mock_use_case.execute.assert_called_once_with(empty_request)
        assert result == expected_response
        assert result.batch_size == 0
    
    def test_get_router(self):
        """Test de obtención del router."""
        router = self.controller.get_router()
        assert router == self.controller.router
        assert len(router.routes) == 1  # Solo el endpoint /analyze
    
    def test_router_route_configuration(self):
        """Test de configuración de rutas del router."""
        router = self.controller.get_router()
        route = router.routes[0]
        
        assert route.path == "/analyze"
        assert route.methods == {"POST"}
        assert route.endpoint is not None


class TestAnalysisControllerIntegration:
    """Tests de integración para AnalysisController."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.mock_use_case = Mock(spec=AnalyzeThreatLogsUseCase)
        self.controller = AnalysisController(self.mock_use_case)
    
    @pytest.mark.integration
    def test_full_analysis_flow(self):
        """Test del flujo completo de análisis."""
        request_data = ThreatAnalyzeRequestDTO(
            logs=[
                {
                    "session_id": "sensor_001",
                    "network_packet_size": 1000,
                    "protocol_type": "ICMP",
                    "login_attempts": 20,
                    "session_duration": 500.0,
                    "encryption_used": "None",
                    "ip_reputation_score": 0.1,
                    "failed_logins": 5,
                    "browser_type": "Unknown",
                    "unusual_time_access": 1,
                    "attack_detected": 1
                }
            ]
        )
        
        expected_response = ThreatAnalyzeResponseDTO(
            trace_id="integration-test-123",
            score=0.95,
            decision={
                "action": "block",
                "confidence": 0.95,
                "threat_detected": True,
                "anomaly_detected": True,
                "reasoning": "High anomaly score detected, immediate blocking recommended"
            },
            batch_size=1
        )
        
        self.mock_use_case.execute.return_value = expected_response
        
        endpoint_func = self.controller.router.routes[0].endpoint
        result = endpoint_func(request_data)
        
        # Verificar que se llamó al caso de uso
        self.mock_use_case.execute.assert_called_once_with(request_data)
        
        # Verificar el resultado
        assert result.trace_id == "integration-test-123"
        assert result.score == 0.95
        assert result.decision["threat_detected"] is True
        assert result.decision["action"] == "block"
        assert result.batch_size == 1
    
    @pytest.mark.integration
    def test_analysis_with_different_device_types(self):
        """Test de análisis con diferentes tipos de dispositivos."""
        request_data = ThreatAnalyzeRequestDTO(
            logs=[
                {
                    "session_id": "thermostat_001",
                    "network_packet_size": 100,
                    "protocol_type": "TCP",
                    "login_attempts": 3,
                    "session_duration": 100.0,
                    "encryption_used": "AES",
                    "ip_reputation_score": 0.9,
                    "failed_logins": 0,
                    "browser_type": "Chrome",
                    "unusual_time_access": 0,
                    "attack_detected": 0
                },
                {
                    "session_id": "camera_002",
                    "network_packet_size": 800,
                    "protocol_type": "UDP",
                    "login_attempts": 15,
                    "session_duration": 200.0,
                    "encryption_used": "AES",
                    "ip_reputation_score": 0.7,
                    "failed_logins": 1,
                    "browser_type": "Firefox",
                    "unusual_time_access": 0,
                    "attack_detected": 0
                }
            ]
        )
        
        expected_response = ThreatAnalyzeResponseDTO(
            trace_id="multi-device-test",
            score=0.45,
            decision={
                "action": "monitor",
                "confidence": 0.75,
                "threat_detected": False,
                "anomaly_detected": False,
                "reasoning": "Normal behavior detected across multiple device types"
            },
            batch_size=2
        )
        
        self.mock_use_case.execute.return_value = expected_response
        
        endpoint_func = self.controller.router.routes[0].endpoint
        result = endpoint_func(request_data)
        
        self.mock_use_case.execute.assert_called_once_with(request_data)
        assert result.batch_size == 2
        assert result.decision["action"] == "monitor"


class TestAnalysisControllerEdgeCases:
    """Tests para casos edge del controlador de análisis."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.mock_use_case = Mock(spec=AnalyzeThreatLogsUseCase)
        self.controller = AnalysisController(self.mock_use_case)
    
    def test_analyze_with_none_use_case(self):
        """Test con caso de uso None."""
        # El constructor no valida None, así que esto debería funcionar
        controller = AnalysisController(None)
        assert controller.analyze_use_case is None
    
    def test_analyze_with_invalid_request_type(self):
        """Test con tipo de request inválido."""
        endpoint_func = self.controller.router.routes[0].endpoint
        
        # FastAPI valida automáticamente el tipo, así que esto debería funcionar
        # pero el endpoint fallará al intentar usar el request inválido
        try:
            endpoint_func("invalid_request")
        except Exception as e:
            # Debería fallar por algún error relacionado con el tipo
            assert isinstance(e, (TypeError, AttributeError, ValueError))
    
    def test_analyze_use_case_returns_none(self):
        """Test cuando el caso de uso retorna None."""
        self.mock_use_case.execute.return_value = None
        
        request = ThreatAnalyzeRequestDTO(logs=[])
        endpoint_func = self.controller.router.routes[0].endpoint
        
        result = endpoint_func(request)
        assert result is None
        self.mock_use_case.execute.assert_called_once_with(request)
    
    def test_analyze_use_case_returns_invalid_response(self):
        """Test cuando el caso de uso retorna una respuesta inválida."""
        # Simular una respuesta que no es un ThreatAnalyzeResponseDTO
        invalid_response = {"invalid": "response"}
        self.mock_use_case.execute.return_value = invalid_response
        
        request = ThreatAnalyzeRequestDTO(logs=[])
        endpoint_func = self.controller.router.routes[0].endpoint
        
        # Esto debería funcionar ya que FastAPI maneja la serialización
        result = endpoint_func(request)
        assert result == invalid_response
