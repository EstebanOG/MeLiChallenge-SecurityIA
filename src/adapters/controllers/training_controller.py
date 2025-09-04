"""
Controlador para endpoints de entrenamiento del modelo.

Este controlador maneja los endpoints relacionados con el entrenamiento
del modelo de detección de anomalías.
"""

from fastapi import APIRouter, HTTPException
from ...domain.entities.dto import TrainRequestDTO, TrainResponseDTO
from ...application.use_cases.train_iot_model import TrainIoTModelUseCase
from ...application.use_cases.train_iot_model_from_kaggle import TrainIoTModelFromKaggleUseCase


class TrainingController:
    """Controlador para entrenamiento del modelo IoT."""
    
    def __init__(
        self, 
        train_use_case: TrainIoTModelUseCase,
        train_from_kaggle_use_case: TrainIoTModelFromKaggleUseCase
    ):
        self.train_use_case = train_use_case
        self.train_from_kaggle_use_case = train_from_kaggle_use_case
        self.router = APIRouter()
        self._setup_routes()
    
    def _setup_routes(self):
        """Configura las rutas del controlador."""
        
        @self.router.post("/train/iot", response_model=TrainResponseDTO)
        def train_iot_model(req: TrainRequestDTO):
            """
            Entrena el modelo con datos de dispositivos IoT proporcionados.
            
            Args:
                req: Lista de logs de dispositivos IoT para entrenamiento
                
            Returns:
                Estado del entrenamiento
            """
            try:
                return self.train_use_case.execute(req)
            except Exception as e:
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error en entrenamiento: {str(e)}"
                )
        
        @self.router.post("/train/iot/kaggle", response_model=TrainResponseDTO)
        def train_iot_model_from_kaggle():
            """
            Descarga el dataset de IoT desde Kaggle y entrena el modelo.
            
            Returns:
                Estado del entrenamiento con información del dataset
            """
            try:
                return self.train_from_kaggle_use_case.execute()
            except Exception as e:
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error en entrenamiento desde Kaggle: {str(e)}"
                )
    
    def get_router(self):
        """Retorna el router configurado."""
        return self.router
