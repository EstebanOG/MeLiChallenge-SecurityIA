from __future__ import annotations

import json
from pathlib import Path
from typing import Tuple
import pandas as pd

from .kaggle_service import download_and_extract_dataset
from ...domain.entities.dataset_config import (
    DEFAULT_IOT_DATASET,
    DEFAULT_LABELED_RATIO,
    RANDOM_STATE,
    LABELED_DATASET_FILENAME,
    UNLABELED_DATASET_FILENAME,
    COMPLETE_DATASET_FILENAME,
    DATASET_INFO_FILENAME
)
from ...domain.services.dataset_utils import (
    find_csv_files,
    load_csv_file,
    create_labeled_mask,
    calculate_dataset_stats,
    log_dataset_info,
    log_split_info
)


class IoTDatasetService:
    """
    Servicio para gestionar datasets de IoT para detección de anomalías.
    
    Responsabilidades:
    - Descarga de datasets desde Kaggle
    - Carga y validación de datos
    - División en conjuntos etiquetados/no etiquetados
    - Persistencia de datasets procesados
    """
    
    def __init__(self, base_data_dir: str = "data"):
        self.base_data_dir = Path(base_data_dir)
        self.raw_dir = self.base_data_dir / "raw"
        self.processed_dir = self.base_data_dir / "processed"
        
        # Crear directorios si no existen
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
    
    def download_dataset(self, dataset_name: str = DEFAULT_IOT_DATASET) -> str:
        """
        Descarga el dataset de IoT desde Kaggle.
        
        Args:
            dataset_name: Identificador del dataset en Kaggle
            
        Returns:
            Ruta al directorio del dataset descargado
            
        Raises:
            FileNotFoundError: Si no se puede descargar el dataset
        """
        log_dataset_info(f"Descargando dataset: {dataset_name}", "download")
        
        dataset_path = download_and_extract_dataset(
            dataset=dataset_name,
            dest_dir=str(self.raw_dir)
        )
        
        log_dataset_info(f"Dataset descargado en: {dataset_path}", "success")
        return dataset_path
    
    def load_dataset(self, data_dir: str) -> pd.DataFrame:
        """
        Carga el dataset desde el directorio especificado.
        
        Args:
            data_dir: Ruta al directorio del dataset
            
        Returns:
            DataFrame con los datos cargados
            
        Raises:
            FileNotFoundError: Si no se encuentran archivos CSV
            ValueError: Si el dataset está vacío o corrupto
        """
        # Encontrar archivos CSV
        csv_files = find_csv_files(data_dir)
        data_file = csv_files[0]  # Usar el primer archivo encontrado
        
        log_dataset_info(f"Cargando archivo: {data_file.name}", "loading")
        
        # Cargar archivo CSV
        df = load_csv_file(data_file)
        
        log_dataset_info(f"Dataset cargado: {df.shape[0]} filas × {df.shape[1]} columnas", "success")
        return df
    
    def split_dataset(self, df: pd.DataFrame, labeled_ratio: float = DEFAULT_LABELED_RATIO) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Divide el dataset en porciones etiquetadas y no etiquetadas.
        
        Args:
            df: DataFrame de entrada
            labeled_ratio: Proporción de datos etiquetados a mantener (default: 0.2)
            
        Returns:
            Tupla con (df_etiquetado, df_no_etiquetado)
        """
        if 'label' not in df.columns:
            log_dataset_info("No se encontró columna 'label'. Tratando todo como no etiquetado.", "warning")
            return pd.DataFrame(), df.copy()
        
        # Crear máscaras para datos etiquetados y no etiquetados
        labeled_mask = create_labeled_mask(df)
        labeled_df = df[labeled_mask].copy()
        unlabeled_df = df[~labeled_mask].copy()
        
        # Ajustar cantidad de datos etiquetados si es necesario
        target_labeled_size = int(len(df) * labeled_ratio)
        if len(labeled_df) > target_labeled_size:
            labeled_df = labeled_df.sample(n=target_labeled_size, random_state=RANDOM_STATE)
        
        log_split_info(labeled_df, unlabeled_df, df)
        return labeled_df, unlabeled_df
    
    def save_datasets(self, labeled_df: pd.DataFrame, unlabeled_df: pd.DataFrame) -> None:
        """
        Guarda los datasets procesados en el directorio de datos procesados.
        
        Args:
            labeled_df: Porción etiquetada del dataset
            unlabeled_df: Porción no etiquetada del dataset
        """
        log_dataset_info("Guardando datasets procesados...", "saving")
        
        # Guardar datasets individuales
        self._save_labeled_dataset(labeled_df)
        self._save_unlabeled_dataset(unlabeled_df)
        self._save_complete_dataset(labeled_df, unlabeled_df)
        self._save_dataset_info(labeled_df, unlabeled_df)
        
        log_dataset_info("Todos los datasets han sido guardados exitosamente", "success")
    
    def _save_labeled_dataset(self, labeled_df: pd.DataFrame) -> None:
        """Guarda el dataset etiquetado."""
        if not labeled_df.empty:
            path = self.processed_dir / LABELED_DATASET_FILENAME
            labeled_df.to_csv(path, index=False)
            log_dataset_info(f"Dataset etiquetado guardado: {path}", "saving")
    
    def _save_unlabeled_dataset(self, unlabeled_df: pd.DataFrame) -> None:
        """Guarda el dataset no etiquetado."""
        if not unlabeled_df.empty:
            path = self.processed_dir / UNLABELED_DATASET_FILENAME
            unlabeled_df.to_csv(path, index=False)
            log_dataset_info(f"Dataset no etiquetado guardado: {path}", "saving")
    
    def _save_complete_dataset(self, labeled_df: pd.DataFrame, unlabeled_df: pd.DataFrame) -> None:
        """Guarda el dataset completo."""
        complete_df = pd.concat([labeled_df, unlabeled_df], ignore_index=True)
        path = self.processed_dir / COMPLETE_DATASET_FILENAME
        complete_df.to_csv(path, index=False)
        log_dataset_info(f"Dataset completo guardado: {path}", "saving")
    
    def _save_dataset_info(self, labeled_df: pd.DataFrame, unlabeled_df: pd.DataFrame) -> None:
        """Guarda información del dataset en formato JSON."""
        complete_df = pd.concat([labeled_df, unlabeled_df], ignore_index=True)
        
        # Calcular estadísticas usando utilidades
        info = calculate_dataset_stats(complete_df, labeled_df)
        
        # Guardar archivo JSON
        path = self.processed_dir / DATASET_INFO_FILENAME
        with open(path, 'w') as f:
            json.dump(info, f, indent=2)
        
        log_dataset_info(f"Información del dataset guardada: {path}", "saving")
