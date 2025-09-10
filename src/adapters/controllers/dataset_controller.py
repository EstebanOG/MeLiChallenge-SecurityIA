"""
Controlador para endpoints de información del dataset.

Este controlador maneja los endpoints relacionados con la información
y muestras del dataset procesado.
"""

from fastapi import APIRouter, HTTPException
from ...domain.entities.dto import DatasetInfoDTO, DatasetSampleDTO
from ...application.use_cases.get_dataset_info import GetDatasetInfoUseCase
from ...application.use_cases.get_dataset_sample import GetDatasetSampleUseCase


class DatasetController:
    """Controlador para información del dataset."""
    
    def __init__(
        self, 
        get_info_use_case: GetDatasetInfoUseCase,
        get_sample_use_case: GetDatasetSampleUseCase
    ):
        self.get_info_use_case = get_info_use_case
        self.get_sample_use_case = get_sample_use_case
        self.router = APIRouter()
        self._setup_routes()
    
    def _setup_routes(self):
        """Configura las rutas del controlador."""
        
        @self.router.get("/dataset/info", response_model=DatasetInfoDTO)
        def get_dataset_info():
            """
            Obtiene información sobre el dataset procesado.
            
            Returns:
                Información del dataset incluyendo distribución de clases
            """
            try:
                return self.get_info_use_case.execute()
            except FileNotFoundError as e:
                raise HTTPException(status_code=404, detail=str(e))
            except Exception as e:
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error obteniendo información del dataset: {str(e)}"
                )
        
        @self.router.get("/dataset/sample", response_model=DatasetSampleDTO)
        def get_dataset_sample(size: int = 10):
            """
            Obtiene una muestra del dataset para pruebas.
            
            Args:
                size: Tamaño de la muestra (máximo 100)
                
            Returns:
                Muestra del dataset
            """
            try:
                return self.get_sample_use_case.execute(size)
            except FileNotFoundError as e:
                raise HTTPException(status_code=404, detail=str(e))
            except Exception as e:
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error obteniendo muestra: {str(e)}"
                )
    
    def get_router(self):
        """Retorna el router configurado."""
        return self.router
