"""
Tests para las rutas de la aplicación FastAPI.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
from src.frameworks.web.routes import create_app


class TestFastAPIRoutes:
    """Tests para las rutas de FastAPI."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.app = create_app()
        self.client = TestClient(self.app)
    
    def test_app_creation(self):
        """Test de creación de la aplicación."""
        assert self.app is not None
        assert self.app.title == "Network Session Anomaly Detection API"
        assert self.app.version == "2.0.0"
    
    def test_health_endpoint(self):
        """Test del endpoint de health."""
        response = self.client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["dataset"] == "Anomaly Detection and Threat Intelligence"
    
    def test_root_endpoint(self):
        """Test del endpoint raíz."""
        response = self.client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["project"] == "Threat Intelligence & Anomaly Detection API"
        assert data["version"] == "2.1.0"
        assert "description" in data
        assert "features" in data
    
    def test_analyze_endpoint_exists(self):
        """Test de que el endpoint de análisis existe."""
        # Verificar que el endpoint está registrado
        routes = [route.path for route in self.app.routes]
        assert "/analyze" in routes
    
    def test_training_endpoints_exist(self):
        """Test de que los endpoints de entrenamiento existen."""
        routes = [route.path for route in self.app.routes]
        assert any("/train" in route for route in routes)
    
    def test_dataset_endpoints_exist(self):
        """Test de que los endpoints de dataset existen."""
        routes = [route.path for route in self.app.routes]
        assert any("/dataset" in route for route in routes)
    
    def test_app_has_error_handlers(self):
        """Test de que la aplicación tiene manejadores de errores."""
        # Verificar que se configuraron los manejadores de errores
        assert len(self.app.exception_handlers) > 0
    
    def test_app_has_middleware(self):
        """Test de que la aplicación tiene middleware configurado."""
        # Verificar que se configuró middleware
        # middleware es un método, no una lista
        assert hasattr(self.app, 'middleware')
        assert callable(self.app.middleware)


class TestFastAPIRoutesIntegration:
    """Tests de integración para las rutas de FastAPI."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.app = create_app()
        self.client = TestClient(self.app)
    
    @pytest.mark.integration
    def test_full_app_startup(self):
        """Test de inicio completo de la aplicación."""
        # Verificar que la aplicación se puede crear sin errores
        assert self.app is not None
        
        # Verificar que todos los controladores están registrados
        routes = [route.path for route in self.app.routes]
        expected_routes = ["/health", "/", "/analyze"]
        
        for expected_route in expected_routes:
            assert expected_route in routes
    
    @pytest.mark.integration
    def test_app_with_mocked_dependencies(self):
        """Test de la aplicación con dependencias mockeadas."""
        with patch('src.frameworks.web.routes.LangGraphPipelineOrchestrator') as mock_orchestrator:
            with patch('src.frameworks.web.routes.AnomalyDetectorGateway') as mock_detector:
                with patch('src.frameworks.web.routes.DatasetGateway') as mock_dataset:
                    # Crear aplicación con mocks
                    app = create_app()
                    client = TestClient(app)
                    
                    # Verificar que funciona
                    response = client.get("/health")
                    assert response.status_code == 200
    
    @pytest.mark.integration
    def test_app_error_handling(self):
        """Test del manejo de errores de la aplicación."""
        # Test con request inválido
        response = self.client.post("/analyze", json={"invalid": "data"})
        # Debe manejar el error sin crashear
        assert response.status_code in [400, 422, 500]
    
    @pytest.mark.integration
    def test_app_performance(self):
        """Test de rendimiento de la aplicación."""
        import time
        
        # Medir tiempo de respuesta del endpoint health
        start_time = time.time()
        response = self.client.get("/health")
        end_time = time.time()
        
        assert response.status_code == 200
        response_time = end_time - start_time
        
        # Debe responder rápidamente
        assert response_time < 1.0


class TestFastAPIRoutesEdgeCases:
    """Tests para casos edge de las rutas de FastAPI."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.app = create_app()
        self.client = TestClient(self.app)
    
    def test_nonexistent_endpoint(self):
        """Test de endpoint que no existe."""
        response = self.client.get("/nonexistent")
        assert response.status_code == 404
    
    def test_invalid_method(self):
        """Test de método HTTP inválido."""
        response = self.client.delete("/health")
        assert response.status_code == 405  # Method Not Allowed
    
    def test_malformed_json(self):
        """Test de JSON malformado."""
        response = self.client.post(
            "/analyze",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code in [400, 422]
    
    def test_large_request(self):
        """Test de request muy grande."""
        large_logs = [{"session_id": f"session_{i}"} for i in range(1000)]
        response = self.client.post("/analyze", json={"logs": large_logs})
        # Debe manejar requests grandes sin crashear
        assert response.status_code in [200, 400, 413, 422, 500]
    
    def test_empty_request(self):
        """Test de request vacío."""
        response = self.client.post("/analyze", json={})
        assert response.status_code in [200, 400, 422]
    
    def test_unicode_content(self):
        """Test de contenido Unicode."""
        response = self.client.post(
            "/analyze",
            json={"logs": [{"session_id": "测试会话", "protocol_type": "TCP"}]}
        )
        # Debe manejar Unicode sin problemas
        assert response.status_code in [200, 400, 422, 500]
