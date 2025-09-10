"""
Router principal de la aplicación FastAPI

Este archivo actúa como un punto de entrada que orquesta
todos los controladores y maneja la configuración de la aplicación.
"""

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError

from ...frameworks.orchestration.langgraph_orchestrator import LangGraphPipelineOrchestrator

from ...adapters.controllers.analysis_controller import AnalysisController
from ...adapters.controllers.dataset_controller import DatasetController
from ...adapters.controllers.supervised_model_controller import SupervisedModelController
from ...adapters.controllers.unsupervised_training_controller import UnsupervisedTrainingController
from ...adapters.controllers.health_controller import router as health_router
from ...adapters.presenters.error_handler import ErrorHandler
from ...adapters.gateways.anomaly_detector_gateway import AnomalyDetectorGateway
from ...adapters.gateways.dataset_service_adapter import DatasetServiceAdapter
from ...adapters.gateways.dataset_validation_gateway import FileSystemDatasetValidationGateway
from ...adapters.ml.supervised_model_adapter import SupervisedModelAdapter
from ...adapters.ml.supervised_threat_detector_adapter import SupervisedThreatDetectorAdapter

from ...application.use_cases.analyze_logs import AnalyzeThreatLogsUseCase
from ...application.use_cases.train_supervised_model import TrainSupervisedModelUseCase
from ...application.use_cases.train_unsupervised_model import TrainUnsupervisedModelUseCase
from ...application.use_cases.get_dataset_info import GetDatasetInfoUseCase
from ...application.use_cases.get_dataset_sample import GetDatasetSampleUseCase
from ...application.use_cases.download_dataset_from_kaggle import DownloadDatasetFromKaggleUseCase




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
    dataset_service_adapter = DatasetServiceAdapter()
    dataset_validation_gateway = FileSystemDatasetValidationGateway()
    
    # Crear adaptador del modelo supervisado
    supervised_model_adapter = SupervisedModelAdapter()
    
    # Crear adaptador del detector de amenazas
    threat_detector_adapter = SupervisedThreatDetectorAdapter()
    
    # Crear servicios de orquestación con detector
    orchestrator = LangGraphPipelineOrchestrator(threat_detector_adapter, anomaly_detector)
    
    # Crear casos de uso
    analyze_use_case = AnalyzeThreatLogsUseCase(orchestrator, supervised_model_adapter)
    train_supervised_use_case = TrainSupervisedModelUseCase(supervised_model_adapter, dataset_validation_gateway)
    train_unsupervised_use_case = TrainUnsupervisedModelUseCase(anomaly_detector, dataset_validation_gateway)
    get_info_use_case = GetDatasetInfoUseCase()
    get_sample_use_case = GetDatasetSampleUseCase()
    download_use_case = DownloadDatasetFromKaggleUseCase(dataset_service_adapter)
    
    # Crear controladores
    analysis_controller = AnalysisController(analyze_use_case)
    supervised_model_controller = SupervisedModelController(train_supervised_use_case)
    unsupervised_training_controller = UnsupervisedTrainingController(train_unsupervised_use_case)
    dataset_controller = DatasetController(get_info_use_case, get_sample_use_case, download_use_case)
    
    # Registrar controladores
    app.include_router(health_router)
    app.include_router(analysis_controller.get_router())
    app.include_router(supervised_model_controller.get_router())
    app.include_router(unsupervised_training_controller.get_router())
    app.include_router(dataset_controller.get_router())
    
    return app


# Crear la aplicación
app = create_app()
