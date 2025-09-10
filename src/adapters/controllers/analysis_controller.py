"""
Controlador para endpoints de análisis de logs de threat intelligence.

Este controlador maneja los endpoints relacionados con el análisis
de logs de sesiones de red para detectar amenazas.
"""

from fastapi import APIRouter, HTTPException
from ...domain.entities.dto import ThreatAnalyzeRequestDTO, ThreatAnalyzeResponseDTO
from ...application.use_cases.analyze_logs import AnalyzeThreatLogsUseCase


class AnalysisController:
    """Controlador para análisis de logs de threat intelligence."""
    
    def __init__(self, analyze_use_case: AnalyzeThreatLogsUseCase):
        self.analyze_use_case = analyze_use_case
        self.router = APIRouter()
        self._setup_routes()
    
    def _setup_routes(self):
        """Configura las rutas del controlador."""
        
        @self.router.post("/analyze", response_model=ThreatAnalyzeResponseDTO)
        def analyze_threat_batch(req: ThreatAnalyzeRequestDTO):
            """
            Analiza un lote de logs de threat intelligence para detectar amenazas.
            
            Args:
                req: Lista de logs de sesiones de red
                
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
