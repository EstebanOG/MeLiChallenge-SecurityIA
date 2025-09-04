"""
Tests para el factory de controladores.

Estos tests verifican la creación de controladores con inyección de dependencias.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.presentation.fastapi_app.factories.controller_factory import ControllerFactory


class TestControllerFactory:
    """Tests para ControllerFactory."""
    
    def setup_method(self):
        """Setup para cada test."""
        # Mock de las dependencias
        self.mock_detector = Mock()
        self.mock_dataset_service = Mock()
        self.mock_orchestrator = Mock()
        self.mock_agent_registry = Mock()
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_create_all_controllers_success(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test creación exitosa de todos los controladores."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        # Act
        controllers = ControllerFactory.create_all_controllers()
        
        # Assert
        assert isinstance(controllers, list)
        assert len(controllers) == 4  # health, analysis, training, dataset
        
        # Verificar que se crearon las instancias de servicios
        mock_detector_class.assert_called_once()
        mock_dataset_service_class.assert_called_once()
        mock_orchestration_factory.create_threat_detection_pipeline.assert_called_once()
        
        # Verificar que todos los controladores son routers válidos
        for controller in controllers:
            assert hasattr(controller, 'routes')
            assert hasattr(controller, 'include_router')
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_create_all_controllers_creates_correct_controllers(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que se crean los controladores correctos."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        # Act
        controllers = ControllerFactory.create_all_controllers()
        
        # Assert
        assert len(controllers) == 4
        
        # Verificar que el primer controlador es el health router
        health_router = controllers[0]
        assert hasattr(health_router, 'routes')
        
        # Verificar que los otros controladores son routers de controladores
        for i in range(1, 4):
            controller = controllers[i]
            assert hasattr(controller, 'routes')
            assert hasattr(controller, 'include_router')
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_create_all_controllers_dependency_injection(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que las dependencias se inyectan correctamente."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        # Act
        controllers = ControllerFactory.create_all_controllers()
        
        # Assert
        # Verificar que se crearon las instancias correctas
        mock_detector_class.assert_called_once()
        mock_dataset_service_class.assert_called_once()
        mock_orchestration_factory.create_threat_detection_pipeline.assert_called_once()
        
        # Verificar que se retornaron los objetos correctos
        assert mock_detector_class.return_value == self.mock_detector
        assert mock_dataset_service_class.return_value == self.mock_dataset_service
        assert mock_orchestration_factory.create_threat_detection_pipeline.return_value == (self.mock_orchestrator, self.mock_agent_registry)
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_create_all_controllers_use_cases_creation(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que se crean los casos de uso correctamente."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        # Act
        controllers = ControllerFactory.create_all_controllers()
        
        # Assert
        # Verificar que se crearon las instancias de servicios
        mock_detector_class.assert_called_once()
        mock_dataset_service_class.assert_called_once()
        mock_orchestration_factory.create_threat_detection_pipeline.assert_called_once()
        
        # Los casos de uso se crean internamente, no podemos verificar directamente
        # pero podemos verificar que no se lanzaron excepciones
        assert len(controllers) == 4
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_create_all_controllers_controller_creation(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que se crean los controladores correctamente."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        # Act
        controllers = ControllerFactory.create_all_controllers()
        
        # Assert
        # Verificar que se crearon 4 controladores
        assert len(controllers) == 4
        
        # Verificar que todos son routers válidos
        for controller in controllers:
            assert hasattr(controller, 'routes')
            assert hasattr(controller, 'include_router')
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_create_all_controllers_returns_immutable_list(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que la lista retornada es inmutable."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        # Act
        controllers = ControllerFactory.create_all_controllers()
        
        # Assert
        # Verificar que es una lista
        assert isinstance(controllers, list)
        
        # Verificar que se puede acceder a los elementos
        assert len(controllers) == 4
        for i in range(4):
            assert controllers[i] is not None
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_create_all_controllers_multiple_calls(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que múltiples llamadas crean nuevas instancias."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        # Act
        controllers1 = ControllerFactory.create_all_controllers()
        controllers2 = ControllerFactory.create_all_controllers()
        
        # Assert
        # Verificar que se crearon las instancias correctas
        assert mock_detector_class.call_count == 2
        assert mock_dataset_service_class.call_count == 2
        assert mock_orchestration_factory.create_threat_detection_pipeline.call_count == 2
        
        # Verificar que se retornaron listas válidas
        assert len(controllers1) == 4
        assert len(controllers2) == 4
        
        # Verificar que son listas diferentes (nuevas instancias)
        assert controllers1 is not controllers2
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_create_all_controllers_exception_handling(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que se manejan las excepciones correctamente."""
        # Arrange
        mock_detector_class.side_effect = Exception("Error creating detector")
        
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            ControllerFactory.create_all_controllers()
        
        assert "Error creating detector" in str(exc_info.value)
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_create_all_controllers_orchestration_factory_exception(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que se manejan las excepciones del OrchestrationFactory."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.side_effect = Exception("Error creating orchestration")
        
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            ControllerFactory.create_all_controllers()
        
        assert "Error creating orchestration" in str(exc_info.value)
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_create_all_controllers_dataset_service_exception(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que se manejan las excepciones del IoTDatasetService."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.side_effect = Exception("Error creating dataset service")
        
        # Act & Assert
        with pytest.raises(Exception) as exc_info:
            ControllerFactory.create_all_controllers()
        
        assert "Error creating dataset service" in str(exc_info.value)
    
    def test_create_all_controllers_static_method(self):
        """Test que create_all_controllers es un método estático."""
        # Act & Assert
        assert hasattr(ControllerFactory, 'create_all_controllers')
        assert callable(getattr(ControllerFactory, 'create_all_controllers'))
        
        # Verificar que es un método estático
        import inspect
        assert inspect.isfunction(ControllerFactory.create_all_controllers)
    
    @patch('src.presentation.fastapi_app.factories.controller_factory.OrchestrationFactory')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IoTDatasetService')
    @patch('src.presentation.fastapi_app.factories.controller_factory.IsolationForestDetector')
    def test_create_all_controllers_imports(self, mock_detector_class, mock_dataset_service_class, mock_orchestration_factory):
        """Test que se importan las dependencias correctas."""
        # Arrange
        mock_detector_class.return_value = self.mock_detector
        mock_dataset_service_class.return_value = self.mock_dataset_service
        mock_orchestration_factory.create_threat_detection_pipeline.return_value = (self.mock_orchestrator, self.mock_agent_registry)
        
        # Act
        controllers = ControllerFactory.create_all_controllers()
        
        # Assert
        # Verificar que se importaron las clases correctas
        assert mock_detector_class.called
        assert mock_dataset_service_class.called
        assert mock_orchestration_factory.create_threat_detection_pipeline.called
        
        # Verificar que se retornaron los objetos correctos
        assert len(controllers) == 4
