"""
Caso de uso para obtener una muestra del dataset.

Este caso de uso encapsula la lógica de negocio para obtener una muestra
del dataset para pruebas.
"""

import pandas as pd
from pathlib import Path
from typing import List, Dict, Any
from ...domain.entities.dto import DatasetSampleDTO


class GetDatasetSampleUseCase:
    """Caso de uso para obtener una muestra del dataset."""
    
    def execute(self, size: int = 10) -> DatasetSampleDTO:
        """
        Obtiene una muestra del dataset para pruebas.
        
        Args:
            size: Tamaño de la muestra (máximo 100)
            
        Returns:
            DTO con la muestra del dataset
        """
        size = min(size, 100)  # Limitar tamaño máximo
        
        processed_dir = Path("data/processed")
        complete_file = processed_dir / "dataset_complete.csv"
        
        if not complete_file.exists():
            raise FileNotFoundError(
                "Dataset no encontrado. Ejecuta /train/iot/kaggle primero."
            )
        
        df = pd.read_csv(complete_file)
        sample = df.sample(n=size, random_state=42)
        
        return DatasetSampleDTO(
            sample_size=len(sample),
            total_rows=len(df),
            data=sample.to_dict('records')
        )

