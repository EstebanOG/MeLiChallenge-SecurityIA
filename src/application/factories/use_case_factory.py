"""
Factory para crear casos de uso con inyección de dependencias.

Este factory está en la capa de aplicación y recibe dependencias ya creadas.
Sigue los principios de Clean Architecture sin conocer la infraestructura directamente.
"""

from ..use_cases.analyze_iot_logs import AnalyzeIoTLogsUseCase
from ..use_cases.train_iot_model import TrainIoTModelUseCase
from ..use_cases.train_iot_model_from_kaggle import TrainIoTModelFromKaggleUseCase
from ..use_cases.get_dataset_info import GetDatasetInfoUseCase
from ..use_cases.get_dataset_sample import GetDatasetSampleUseCase


class UseCaseFactory:
    """Factory para crear casos de uso con dependencias inyectadas."""
    
    @staticmethod
    def create_all_use_cases(dependencies: dict):
        """
        Crea todos los casos de uso con sus dependencias inyectadas.
        
        Args:
            dependencies: Diccionario con las dependencias ya creadas
        
        Returns:
            Diccionario con todos los casos de uso creados
        """
        # Crear casos de uso con dependencias inyectadas
        analyze_use_case = AnalyzeIoTLogsUseCase(
            dependencies['orchestrator'], 
            dependencies['agent_registry']
        )
        train_use_case = TrainIoTModelUseCase(dependencies['detector'])
        train_from_kaggle_use_case = TrainIoTModelFromKaggleUseCase(
            dependencies['detector'], 
            dependencies['dataset_service']
        )
        get_info_use_case = GetDatasetInfoUseCase()
        get_sample_use_case = GetDatasetSampleUseCase()
        
        return {
            'analyze_use_case': analyze_use_case,
            'train_use_case': train_use_case,
            'train_from_kaggle_use_case': train_from_kaggle_use_case,
            'get_info_use_case': get_info_use_case,
            'get_sample_use_case': get_sample_use_case
        }
