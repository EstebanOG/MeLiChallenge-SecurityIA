"""
Controlador para endpoints del modelo supervisado.

Este controlador maneja los endpoints relacionados con el entrenamiento
y estado del modelo supervisado de detección de amenazas.
"""

from fastapi import APIRouter, HTTPException
from ...domain.entities.dto import SupervisedTrainResponseDTO
from ...application.use_cases.train_supervised_model import TrainSupervisedModelUseCase


class SupervisedModelController:
    """Controlador para el modelo supervisado."""
    
    def __init__(self, train_use_case: TrainSupervisedModelUseCase):
        self.train_use_case = train_use_case
        self.router = APIRouter()
        self._setup_routes()
    
    def _setup_routes(self):
        """Configura las rutas del controlador."""
        
        @self.router.post("/train/supervised", response_model=SupervisedTrainResponseDTO)
        def train_supervised_model():
            """
            Entrena el modelo supervisado de detección de amenazas.
            
            Returns:
                Estado del entrenamiento del modelo supervisado
            """
            try:
                return self.train_use_case.execute()
            except Exception as e:
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error en entrenamiento del modelo supervisado: {str(e)}"
                )
        
        @self.router.get("/model/supervised/status")
        def get_supervised_model_status():
            """
            Obtiene el estado del modelo supervisado.
            
            Returns:
                Estado actual del modelo supervisado
            """
            try:
                return self.train_use_case.get_model_status()
            except Exception as e:
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error obteniendo estado del modelo: {str(e)}"
                )
        
        @self.router.get("/model/supervised/health")
        def check_supervised_model_health():
            """
            Verifica si el modelo supervisado está listo para usar.
            
            Returns:
                Estado de salud del modelo supervisado
            """
            try:
                is_trained = self.train_use_case.is_model_trained()
                
                if is_trained:
                    return {
                        "status": "healthy",
                        "message": "Modelo supervisado está entrenado y listo para usar",
                        "is_trained": True
                    }
                else:
                    return {
                        "status": "not_ready",
                        "message": "Modelo supervisado no está entrenado. Usa POST /train/supervised para entrenarlo",
                        "is_trained": False
                    }
            except Exception as e:
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error verificando salud del modelo: {str(e)}"
                )
    
    def get_router(self):
        """Retorna el router configurado."""
        return self.router
