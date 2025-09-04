"""
Controlador para endpoints de análisis de logs IoT.

Este controlador maneja los endpoints relacionados con el análisis
de logs de dispositivos IoT para detectar anomalías.
"""

from fastapi import APIRouter, HTTPException
from ...domain.entities.dto import IoTAnalyzeRequestDTO, IoTAnalyzeResponseDTO
from ...application.use_cases.analyze_iot_logs import AnalyzeIoTLogsUseCase


class AnalysisController:
    """Controlador para análisis de logs IoT."""
    
    def __init__(self, analyze_use_case: AnalyzeIoTLogsUseCase):
        self.analyze_use_case = analyze_use_case
        self.router = APIRouter()
        self._setup_routes()
    
    def _setup_routes(self):
        """Configura las rutas del controlador."""
        
        @self.router.post("/analyze", response_model=IoTAnalyzeResponseDTO)
        def analyze_iot_batch(req: IoTAnalyzeRequestDTO):
            """
            Analiza un lote de logs de dispositivos IoT para detectar anomalías.
            
            Args:
                req: Lista de logs de dispositivos IoT
                
            Returns:
                Resultado del análisis con score y decisión
            """
            try:
                return self.analyze_use_case.execute(req)
            except Exception as e:
                raise HTTPException(
                    status_code=500, 
                    detail=f"Error en análisis: {str(e)}"
                )
    
    def get_router(self):
        """Retorna el router configurado."""
        return self.router
