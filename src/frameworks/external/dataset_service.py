"""
Servicio externo para manejo de datasets.

Este servicio maneja la descarga, carga y procesamiento de datasets
desde fuentes externas como Kaggle.
"""

import os
import json
import pandas as pd
from pathlib import Path
from typing import Tuple, Dict, Any
from .kaggle_service import download_and_extract_dataset

# Configuración por defecto
DEFAULT_DATASET = "dnkumars/cybersecurity-intrusion-detection-dataset"
DEFAULT_LABELED_RATIO = 0.2
DATA_DIR = "data"
PROCESSED_DIR = "data/processed"
RAW_DIR = "data/raw"


class DatasetService:
    """
    Servicio para manejo de datasets externos.
    
    Este servicio proporciona funcionalidades para descargar, cargar
    y procesar datasets desde fuentes externas.
    """
    
    def __init__(self):
        """Inicializa el servicio de datasets."""
        self._ensure_directories()
    
    def _ensure_directories(self) -> None:
        """Asegura que los directorios necesarios existan."""
        Path(DATA_DIR).mkdir(exist_ok=True)
        Path(PROCESSED_DIR).mkdir(exist_ok=True)
        Path(RAW_DIR).mkdir(exist_ok=True)
    
    def download_dataset(self, dataset_name: str = DEFAULT_DATASET) -> str:
        """
        Descarga un dataset desde Kaggle.
        
        Args:
            dataset_name: Nombre del dataset en Kaggle
            
        Returns:
            Ruta al directorio donde se extrajo el dataset
        """
        try:
            download_path = download_and_extract_dataset(dataset_name)
            print(f"✅ Dataset descargado exitosamente en: {download_path}")
            return download_path
        except Exception as e:
            print(f"❌ Error descargando dataset: {e}")
            raise
    
    def load_dataset(self, data_dir: str) -> pd.DataFrame:
        """
        Carga un dataset desde un directorio.
        
        Args:
            data_dir: Directorio que contiene el dataset
            
        Returns:
            DataFrame con los datos del dataset
        """
        try:
            # Buscar archivos CSV en el directorio
            csv_files = list(Path(data_dir).glob("*.csv"))
            if not csv_files:
                raise FileNotFoundError(f"No se encontraron archivos CSV en {data_dir}")
            
            # Cargar el primer archivo CSV encontrado
            csv_file = csv_files[0]
            df = pd.read_csv(csv_file)
            print(f"✅ Dataset cargado: {len(df)} filas, {len(df.columns)} columnas")
            return df
        except Exception as e:
            print(f"❌ Error cargando dataset: {e}")
            raise
    
    def save_complete_dataset(self, df: pd.DataFrame) -> None:
        """
        Guarda el dataset completo sin procesar.
        
        Args:
            df: DataFrame con el dataset completo
        """
        try:
            complete_path = os.path.join(PROCESSED_DIR, "dataset_complete.csv")
            df.to_csv(complete_path, index=False)
            
            # Guardar información básica
            info = {
                "total_rows": len(df),
                "columns": list(df.columns),
                "file_path": complete_path
            }
            
            info_path = os.path.join(PROCESSED_DIR, "dataset_info.json")
            with open(info_path, 'w') as f:
                json.dump(info, f, indent=2)
            
            print(f"✅ Dataset completo guardado en {complete_path}")
        except Exception as e:
            print(f"❌ Error guardando dataset completo: {e}")
            raise
    
    def _save_dataset_info(self, labeled_df: pd.DataFrame, unlabeled_df: pd.DataFrame) -> None:
        """
        Guarda información del dataset procesado.
        
        Args:
            labeled_df: DataFrame con datos etiquetados
            unlabeled_df: DataFrame con datos no etiquetados
        """
        try:
            info = {
                "total_rows": len(labeled_df) + len(unlabeled_df),
                "labeled_rows": len(labeled_df),
                "unlabeled_rows": len(unlabeled_df),
                "columns": list(labeled_df.columns),
                "label_distribution": labeled_df['attack_detected'].value_counts().to_dict() if 'attack_detected' in labeled_df.columns else {},
                "anomaly_ratio": labeled_df['attack_detected'].mean() if 'attack_detected' in labeled_df.columns else 0.0
            }
            
            info_path = os.path.join(PROCESSED_DIR, "dataset_info.json")
            with open(info_path, 'w') as f:
                json.dump(info, f, indent=2)
        except Exception as e:
            print(f"⚠️ Error guardando información del dataset: {e}")
    
    def get_dataset_info(self) -> Dict[str, Any]:
        """
        Obtiene información del dataset procesado.
        
        Returns:
            Diccionario con información del dataset
        """
        try:
            info_path = os.path.join(PROCESSED_DIR, "dataset_info.json")
            if not os.path.exists(info_path):
                return {"error": "Dataset no encontrado"}
            
            with open(info_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            return {"error": f"Error cargando información: {str(e)}"}
    
    def get_dataset_sample(self, size: int = 10) -> Dict[str, Any]:
        """
        Obtiene una muestra del dataset procesado.
        
        Args:
            size: Tamaño de la muestra
            
        Returns:
            Diccionario con la muestra del dataset
        """
        try:
            complete_path = os.path.join(PROCESSED_DIR, "dataset_complete.csv")
            if not os.path.exists(complete_path):
                return {"error": "Dataset no encontrado"}
            
            df = pd.read_csv(complete_path)
            sample_df = df.sample(n=min(size, len(df)), random_state=42)
            
            return {
                "sample_size": len(sample_df),
                "total_rows": len(df),
                "data": sample_df.to_dict('records')
            }
        except Exception as e:
            return {"error": f"Error obteniendo muestra: {str(e)}"}
