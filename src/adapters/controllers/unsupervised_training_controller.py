"""
Controlador para endpoints de entrenamiento del modelo no supervisado.

Este controlador maneja los endpoints relacionados con el entrenamiento
del modelo de detección de anomalías no supervisado.
"""

from fastapi import APIRouter, HTTPException
from ...domain.entities.dto import UnsupervisedTrainResponseDTO
from ...application.use_cases.train_unsupervised_model import TrainUnsupervisedModelUseCase


class UnsupervisedTrainingController:
    """Controlador para entrenamiento del modelo no supervisado."""
    
    def __init__(self, train_unsupervised_use_case: TrainUnsupervisedModelUseCase):
        self.train_unsupervised_use_case = train_unsupervised_use_case
        self.router = APIRouter()
        self._setup_routes()
    
    def _setup_routes(self):
        """Configura las rutas del controlador."""
        
        @self.router.post("/train/unsupervised", response_model=UnsupervisedTrainResponseDTO)
        def train_unsupervised_model():
            """
            Entrena el modelo no supervisado con el dataset completo.
            
            Returns:
                Estado del entrenamiento del modelo no supervisado
            """
            try:
                return self.train_unsupervised_use_case.execute()
            except FileNotFoundError as e:
                raise HTTPException(
                    status_code=404, 
                    detail=f"Dataset no encontrado: {str(e)}"
                )
            except Exception as e:
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error en entrenamiento no supervisado: {str(e)}"
                )
        
        @self.router.get("/train/unsupervised/status")
        def get_unsupervised_model_status():
            """
            Obtiene el estado del modelo no supervisado.
            
            Returns:
                Estado actual del modelo no supervisado
            """
            try:
                return self.train_unsupervised_use_case.get_model_status()
            except Exception as e:
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error obteniendo estado del modelo: {str(e)}"
                )
    
    def get_router(self):
        """Retorna el router configurado."""
        return self.router
