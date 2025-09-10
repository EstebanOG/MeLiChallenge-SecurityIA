"""
Tests para el controlador de health.
"""

import pytest
from fastapi.testclient import TestClient
from src.adapters.controllers.health_controller import router
from src.domain.entities.dto import HealthResponseDTO, InfoResponseDTO


class TestHealthController:
    """Tests para el controlador de health."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.client = TestClient(router)
    
    def test_health_endpoint_success(self):
        """Test del endpoint de health exitoso."""
        response = self.client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["dataset"] == "Anomaly Detection and Threat Intelligence"
    
    def test_health_endpoint_response_model(self):
        """Test del modelo de respuesta del endpoint health."""
        response = self.client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        
        # Verificar que la respuesta coincide con HealthResponseDTO
        assert "status" in data
        assert "dataset" in data
        assert data["status"] == "ok"
        assert data["dataset"] == "Anomaly Detection and Threat Intelligence"
    
    def test_info_endpoint_success(self):
        """Test del endpoint de info exitoso."""
        response = self.client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["project"] == "Threat Intelligence & Anomaly Detection API"
        assert data["version"] == "2.1.0"
        assert "description" in data
        assert "features" in data
    
    def test_info_endpoint_response_model(self):
        """Test del modelo de respuesta del endpoint info."""
        response = self.client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        
        # Verificar que la respuesta coincide con InfoResponseDTO
        assert "project" in data
        assert "version" in data
        assert "description" in data
        assert "features" in data
        
        assert data["project"] == "Threat Intelligence & Anomaly Detection API"
        assert data["version"] == "2.1.0"
        assert isinstance(data["features"], list)
        assert len(data["features"]) > 0
    
    def test_info_endpoint_features(self):
        """Test de las características del endpoint info."""
        response = self.client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        
        features = data["features"]
        assert isinstance(features, list)
        assert "Detección de anomalías en tiempo real" in features
    
    def test_health_endpoint_methods(self):
        """Test de los métodos HTTP permitidos para health."""
        # GET debería funcionar
        response = self.client.get("/health")
        assert response.status_code == 200
        
        # POST no debería funcionar
        response = self.client.post("/health")
        assert response.status_code == 405  # Method Not Allowed
    
    def test_info_endpoint_methods(self):
        """Test de los métodos HTTP permitidos para info."""
        # GET debería funcionar
        response = self.client.get("/")
        assert response.status_code == 200
        
        # POST no debería funcionar
        response = self.client.post("/")
        assert response.status_code == 405  # Method Not Allowed
    
    def test_health_endpoint_headers(self):
        """Test de los headers de respuesta del endpoint health."""
        response = self.client.get("/health")
        
        assert response.status_code == 200
        assert "content-type" in response.headers
        assert "application/json" in response.headers["content-type"]
    
    def test_info_endpoint_headers(self):
        """Test de los headers de respuesta del endpoint info."""
        response = self.client.get("/")
        
        assert response.status_code == 200
        assert "content-type" in response.headers
        assert "application/json" in response.headers["content-type"]
    
    def test_health_endpoint_consistency(self):
        """Test de consistencia del endpoint health en múltiples llamadas."""
        # Primera llamada
        response1 = self.client.get("/health")
        assert response1.status_code == 200
        data1 = response1.json()
        
        # Segunda llamada
        response2 = self.client.get("/health")
        assert response2.status_code == 200
        data2 = response2.json()
        
        # Las respuestas deben ser idénticas
        assert data1 == data2
        assert data1["status"] == data2["status"]
        assert data1["dataset"] == data2["dataset"]
    
    def test_info_endpoint_consistency(self):
        """Test de consistencia del endpoint info en múltiples llamadas."""
        # Primera llamada
        response1 = self.client.get("/")
        assert response1.status_code == 200
        data1 = response1.json()
        
        # Segunda llamada
        response2 = self.client.get("/")
        assert response2.status_code == 200
        data2 = response2.json()
        
        # Las respuestas deben ser idénticas
        assert data1 == data2
        assert data1["project"] == data2["project"]
        assert data1["version"] == data2["version"]


class TestHealthControllerIntegration:
    """Tests de integración para el controlador de health."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.client = TestClient(router)
    
    @pytest.mark.integration
    def test_health_and_info_endpoints_together(self):
        """Test de ambos endpoints funcionando juntos."""
        # Llamar a ambos endpoints
        health_response = self.client.get("/health")
        info_response = self.client.get("/")
        
        # Ambos deben funcionar
        assert health_response.status_code == 200
        assert info_response.status_code == 200
        
        health_data = health_response.json()
        info_data = info_response.json()
        
        # Verificar que son diferentes
        assert health_data != info_data
        assert "status" in health_data
        assert "project" in info_data
    
    @pytest.mark.integration
    def test_endpoints_with_different_accept_headers(self):
        """Test de endpoints con diferentes headers Accept."""
        # Sin header Accept
        response1 = self.client.get("/health")
        assert response1.status_code == 200
        
        # Con header Accept JSON
        response2 = self.client.get("/health", headers={"Accept": "application/json"})
        assert response2.status_code == 200
        
        # Con header Accept wildcard
        response3 = self.client.get("/health", headers={"Accept": "*/*"})
        assert response3.status_code == 200
        
        # Todas las respuestas deben ser idénticas
        assert response1.json() == response2.json() == response3.json()
    
    @pytest.mark.integration
    def test_endpoints_performance(self):
        """Test de rendimiento de los endpoints."""
        import time
        
        # Medir tiempo de respuesta del endpoint health
        start_time = time.time()
        response = self.client.get("/health")
        end_time = time.time()
        
        assert response.status_code == 200
        response_time = end_time - start_time
        
        # El endpoint debe responder rápidamente (menos de 1 segundo)
        assert response_time < 1.0
    
    @pytest.mark.integration
    def test_endpoints_concurrent_requests(self):
        """Test de requests concurrentes a los endpoints."""
        import threading
        import time
        
        results = []
        
        def make_request(endpoint):
            response = self.client.get(endpoint)
            results.append((endpoint, response.status_code, response.json()))
        
        # Crear múltiples threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=make_request, args=("/health",))
            threads.append(thread)
            thread = threading.Thread(target=make_request, args=("/",))
            threads.append(thread)
        
        # Ejecutar todos los threads
        for thread in threads:
            thread.start()
        
        # Esperar a que terminen
        for thread in threads:
            thread.join()
        
        # Verificar que todos los requests fueron exitosos
        assert len(results) == 10  # 5 health + 5 info
        
        for endpoint, status_code, data in results:
            assert status_code == 200
            if endpoint == "/health":
                assert data["status"] == "ok"
            elif endpoint == "/":
                assert data["project"] == "Threat Intelligence & Anomaly Detection API"


class TestHealthControllerEdgeCases:
    """Tests para casos edge del controlador de health."""
    
    def setup_method(self):
        """Configuración inicial para cada test."""
        self.client = TestClient(router)
    
    def test_health_endpoint_with_query_params(self):
        """Test del endpoint health con parámetros de query."""
        response = self.client.get("/health?test=value")
        
        # Debe ignorar los query params y funcionar normalmente
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
    
    def test_info_endpoint_with_query_params(self):
        """Test del endpoint info con parámetros de query."""
        response = self.client.get("/?test=value&another=param")
        
        # Debe ignorar los query params y funcionar normalmente
        assert response.status_code == 200
        data = response.json()
        assert data["project"] == "Threat Intelligence & Anomaly Detection API"
    
    def test_health_endpoint_with_extra_headers(self):
        """Test del endpoint health con headers extra."""
        response = self.client.get("/health", headers={
            "X-Custom-Header": "test-value",
            "User-Agent": "test-agent"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
    
    def test_info_endpoint_with_extra_headers(self):
        """Test del endpoint info con headers extra."""
        response = self.client.get("/", headers={
            "X-Custom-Header": "test-value",
            "User-Agent": "test-agent"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["project"] == "Threat Intelligence & Anomaly Detection API"
    
    def test_health_endpoint_case_sensitivity(self):
        """Test de sensibilidad a mayúsculas del endpoint health."""
        # FastAPI es case-sensitive para las rutas
        response = self.client.get("/HEALTH")
        assert response.status_code == 404  # No encontrado
    
    def test_info_endpoint_case_sensitivity(self):
        """Test de sensibilidad a mayúsculas del endpoint info."""
        # FastAPI es case-sensitive para las rutas
        response = self.client.get("/INFO")
        assert response.status_code == 404  # No encontrado
