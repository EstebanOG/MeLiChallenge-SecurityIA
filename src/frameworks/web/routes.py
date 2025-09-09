"""
Router principal de la aplicación FastAPI

Este archivo actúa como un punto de entrada que orquesta
todos los controladores y maneja la configuración de la aplicación.
"""

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError

from ...frameworks.orchestration.langgraph_orchestrator import LangGraphPipelineOrchestrator

from ...adapters.controllers.analysis_controller import AnalysisController
from ...adapters.controllers.training_controller import TrainingController
from ...adapters.controllers.dataset_controller import DatasetController
from ...adapters.controllers.health_controller import router as health_router
from ...adapters.presenters.error_handler import ErrorHandler
from ...adapters.gateways.anomaly_detector_gateway import AnomalyDetectorGateway
from ...adapters.gateways.dataset_gateway import DatasetGateway

from ...application.use_cases.analyze_logs import AnalyzeThreatLogsUseCase
from ...application.use_cases.train_iot_model import TrainIoTModelUseCase
from ...application.use_cases.train_iot_model_from_kaggle import TrainIoTModelFromKaggleUseCase
from ...application.use_cases.get_dataset_info import GetDatasetInfoUseCase
from ...application.use_cases.get_dataset_sample import GetDatasetSampleUseCase




def create_app() -> FastAPI:
    """
    Crea y configura la aplicación FastAPI
    
    Returns:
        Aplicación FastAPI configurada
    """
    app = FastAPI(
        title="Network Session Anomaly Detection API",
        description="API para detección de anomalías en sesiones de red y comportamiento de autenticación",
        version="2.0.0"
    )
    
    # Configurar manejo de errores
    app.add_exception_handler(
        RequestValidationError, 
        ErrorHandler.handle_validation_error
    )
    app.add_exception_handler(
        Exception, 
        ErrorHandler.get_exception_handler()
    )
    
    # Crear gateways (adaptadores)
    anomaly_detector = AnomalyDetectorGateway()
    dataset_gateway = DatasetGateway()
    
    # Crear servicios de orquestación
    orchestrator = LangGraphPipelineOrchestrator()
    
    # Crear casos de uso
    analyze_use_case = AnalyzeThreatLogsUseCase(orchestrator)
    train_use_case = TrainIoTModelUseCase(anomaly_detector)
    train_from_kaggle_use_case = TrainIoTModelFromKaggleUseCase(anomaly_detector, dataset_gateway)
    get_info_use_case = GetDatasetInfoUseCase()
    get_sample_use_case = GetDatasetSampleUseCase()
    
    # Crear controladores
    analysis_controller = AnalysisController(analyze_use_case)
    training_controller = TrainingController(train_use_case, train_from_kaggle_use_case)
    dataset_controller = DatasetController(get_info_use_case, get_sample_use_case)
    
    # Registrar controladores
    app.include_router(health_router)
    app.include_router(analysis_controller.get_router())
    app.include_router(training_controller.get_router())
    app.include_router(dataset_controller.get_router())
    
    return app


# Crear la aplicación
app = create_app()
