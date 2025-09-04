"""
Tests de integración para la aplicación FastAPI.

Estos tests verifican la integración completa de todos los componentes
de la aplicación refactorizada.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from fastapi.testclient import TestClient
from src.presentation.fastapi_app.routes import create_app


class TestFastAPIAppIntegration:
    """Tests de integración para la aplicación FastAPI."""
    
    def setup_method(self):
        """Setup para cada test."""
        # Mock de todas las dependencias
        self.mock_detector = Mock()
        self.mock_dataset_service = Mock()
        self.mock_orchestrator = Mock()
        self.mock_agent_registry = Mock()
        
        # Mock de los casos de uso
        self.mock_analyze_use_case = Mock()
        self.mock_train_use_case = Mock()
        self.mock_train_from_kaggle_use_case = Mock()
        self.mock_get_info_use_case = Mock()
        self.mock_get_sample_use_case = Mock()
        
        # Mock de los resultados de ejecución
        self.mock_execution_result = Mock()
        self.mock_context = Mock()
        self.mock_analysis_result = Mock()
        self.mock_decision_result = Mock()
        
        # Configurar mocks
        self.mock_context.trace_id = "trace_123"
        self.mock_analysis_result.output = {"batch_score": 0.85}
        self.mock_decision_result.output = {"action": "block", "confidence": 0.9}
        self.mock_execution_result.context = self.mock_context
        self.mock_execution_result.get_agent_result.side_effect = lambda agent_type: {
            "analysis": self.mock_analysis_result,
            "decision": self.mock_decision_result
        }.get(agent_type)
        
        # Mock de los casos de uso
        self.mock_analyze_use_case.execute.return_value = self.mock_execution_result
        self.mock_train_use_case.execute.return_value = Mock(
            status="trained",
            samples=1,
            file_path="models/isoforest.joblib",
            features=11
        )
        self.mock_train_from_kaggle_use_case.execute.return_value = Mock(
            status="trained_from_kaggle",
            samples=1000,
            file_path="models/isoforest.joblib",
            features=11
        )
        self.mock_get_info_use_case.execute.return_value = Mock(
            total_rows=1000,
            labeled_rows=200,
            unlabeled_rows=800,
            columns=["timestamp", "device_id", "cpu_usage"],
            label_distribution={"normal": 150, "anomaly": 50},
            device_type_distribution={"thermostat": 100, "sensor": 100},
            anomaly_ratio=0.25
        )
        self.mock_get_sample_use_case.execute.return_value = Mock(
            sample_size=10,
            total_rows=1000,
            data=[{"device_id": f"device_{i:03d}", "cpu_usage": i * 2.0} for i in range(10)]
        )
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_creation_success(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que la aplicación se crea exitosamente."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        # Act
        app = create_app()
        
        # Assert
        assert app is not None
        assert hasattr(app, 'routes')
        assert hasattr(app, 'include_router')
        assert hasattr(app, 'add_exception_handler')
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_health_endpoint(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test endpoint de salud de la aplicación."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        app = create_app()
        client = TestClient(app)
        
        # Act
        response = client.get("/health")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["dataset"] == "IoT Anomaly Detection"
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_info_endpoint(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test endpoint de información de la aplicación."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        app = create_app()
        client = TestClient(app)
        
        # Act
        response = client.get("/")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["project"] == "IoT Anomaly Detection API"
        assert data["version"] == "2.0.0"
        assert "features" in data
        assert "supported_device_types" in data
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_analyze_endpoint(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test endpoint de análisis de la aplicación."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        app = create_app()
        client = TestClient(app)
        
        request_data = {
            "logs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "device_id": "device_001",
                    "device_type": "thermostat",
                    "cpu_usage": 50.0,
                    "memory_usage": 60.0,
                    "network_in_kb": 1000,
                    "network_out_kb": 500,
                    "packet_rate": 100,
                    "avg_response_time_ms": 50.0,
                    "service_access_count": 10,
                    "failed_auth_attempts": 0,
                    "is_encrypted": 1,
                    "geo_location_variation": 0.1,
                    "label": "normal"
                }
            ]
        }
        
        # Act
        response = client.post("/analyze", json=request_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "trace_id" in data
        assert "score" in data
        assert "decision" in data
        assert "batch_size" in data
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_train_endpoint(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test endpoint de entrenamiento de la aplicación."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        app = create_app()
        client = TestClient(app)
        
        request_data = {
            "logs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "device_id": "device_001",
                    "device_type": "thermostat",
                    "cpu_usage": 50.0,
                    "memory_usage": 60.0,
                    "network_in_kb": 1000,
                    "network_out_kb": 500,
                    "packet_rate": 100,
                    "avg_response_time_ms": 50.0,
                    "service_access_count": 10,
                    "failed_auth_attempts": 0,
                    "is_encrypted": 1,
                    "geo_location_variation": 0.1,
                    "label": "normal"
                }
            ]
        }
        
        # Act
        response = client.post("/train/iot", json=request_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "trained"
        assert data["samples"] == 1
        assert data["file_path"] == "models/isoforest.joblib"
        assert data["features"] == 11
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_train_from_kaggle_endpoint(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test endpoint de entrenamiento desde Kaggle de la aplicación."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        app = create_app()
        client = TestClient(app)
        
        # Act
        response = client.post("/train/iot/kaggle")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "trained_from_kaggle"
        assert data["samples"] == 1000
        assert data["file_path"] == "models/isoforest.joblib"
        assert data["features"] == 11
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_dataset_info_endpoint(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test endpoint de información del dataset de la aplicación."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        app = create_app()
        client = TestClient(app)
        
        # Act
        response = client.get("/dataset/info")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["total_rows"] == 1000
        assert data["labeled_rows"] == 200
        assert data["unlabeled_rows"] == 800
        assert "columns" in data
        assert "label_distribution" in data
        assert "device_type_distribution" in data
        assert "anomaly_ratio" in data
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_dataset_sample_endpoint(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test endpoint de muestra del dataset de la aplicación."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        app = create_app()
        client = TestClient(app)
        
        # Act
        response = client.get("/dataset/sample")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["sample_size"] == 10
        assert data["total_rows"] == 1000
        assert "data" in data
        assert len(data["data"]) == 10
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_error_handling(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test manejo de errores en la aplicación."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        app = create_app()
        client = TestClient(app)
        
        # Test con datos inválidos
        invalid_data = {
            "logs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "device_id": "device_001",
                    "device_type": "thermostat",
                    "cpu_usage": -1.0,  # Inválido
                    "memory_usage": 60.0,
                    "network_in_kb": 1000,
                    "network_out_kb": 500,
                    "packet_rate": 100,
                    "avg_response_time_ms": 50.0,
                    "service_access_count": 10,
                    "failed_auth_attempts": 0,
                    "is_encrypted": 1,
                    "geo_location_variation": 0.1,
                    "label": "normal"
                }
            ]
        }
        
        # Act
        response = client.post("/analyze", json=invalid_data)
        
        # Assert
        assert response.status_code == 422  # Validation Error
        data = response.json()
        assert "detail" in data
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_all_endpoints_accessible(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que todos los endpoints están accesibles."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        app = create_app()
        client = TestClient(app)
        
        # Act & Assert
        # Health endpoints
        response = client.get("/health")
        assert response.status_code == 200
        
        response = client.get("/")
        assert response.status_code == 200
        
        # Analysis endpoint
        response = client.post("/analyze", json={"logs": []})
        assert response.status_code == 200
        
        # Training endpoints
        response = client.post("/train/iot", json={"logs": []})
        assert response.status_code == 200
        
        response = client.post("/train/iot/kaggle")
        assert response.status_code == 200
        
        # Dataset endpoints
        response = client.get("/dataset/info")
        assert response.status_code == 200
        
        response = client.get("/dataset/sample")
        assert response.status_code == 200
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_exception_handlers_registered(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que los manejadores de excepciones están registrados."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        # Act
        app = create_app()
        
        # Assert
        # Verificar que la aplicación tiene manejadores de excepciones
        assert hasattr(app, 'exception_handlers')
        assert len(app.exception_handlers) > 0
        
        # Verificar que se registraron los manejadores correctos
        from fastapi.exceptions import RequestValidationError
        assert RequestValidationError in app.exception_handlers
        assert Exception in app.exception_handlers
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_app_controllers_registered(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que todos los controladores están registrados."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        # Act
        app = create_app()
        
        # Assert
        # Verificar que la aplicación tiene rutas
        assert hasattr(app, 'routes')
        assert len(app.routes) > 0
        
        # Verificar que se registraron las rutas correctas
        route_paths = [route.path for route in app.routes]
        assert "/health" in route_paths
        assert "/" in route_paths
        assert "/analyze" in route_paths
        assert "/train/iot" in route_paths
        assert "/train/iot/kaggle" in route_paths
        assert "/dataset/info" in route_paths
        assert "/dataset/sample" in route_paths
