"""
Caso de uso para obtener información del dataset.

Este caso de uso encapsula la lógica de negocio para obtener información
sobre el dataset procesado.
"""

import json
from pathlib import Path
from ...domain.entities.dto import DatasetInfoDTO


class GetDatasetInfoUseCase:
    """Caso de uso para obtener información del dataset."""
    
    def execute(self) -> DatasetInfoDTO:
        """
        Obtiene información sobre el dataset procesado.
        
        Returns:
            DTO con la información del dataset
        """
        processed_dir = Path("data/processed")
        info_file = processed_dir / "dataset_info.json"
        
        if not info_file.exists():
            raise FileNotFoundError(
                "Dataset no encontrado. Ejecuta /train/iot/kaggle primero."
            )
        
        with open(info_file, 'r') as f:
            info = json.load(f)
        
        return DatasetInfoDTO(**info)

