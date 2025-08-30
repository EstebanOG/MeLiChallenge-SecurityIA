"""
Configuración del dominio para datasets de IoT.

Este archivo contiene las entidades y configuraciones del dominio
relacionadas con la gestión de datasets, no detalles de infraestructura.
"""

from pathlib import Path

# Directorios de datos (configuración del dominio)
DATA_DIR = Path("data")
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"

# Dataset por defecto (entidad del dominio) - Dataset válido y disponible
DEFAULT_IOT_DATASET = "ziya07/anomaly-detection-and-threat-intelligence-dataset"

# Configuración de división del dataset (reglas de negocio)
DEFAULT_LABELED_RATIO = 0.2
RANDOM_STATE = 42

# Nombres de archivos de salida (convenciones del dominio)
LABELED_DATASET_FILENAME = "dataset_labeled_20p.csv"
UNLABELED_DATASET_FILENAME = "dataset_unlabeled_80p.csv"
COMPLETE_DATASET_FILENAME = "dataset_complete.csv"
DATASET_INFO_FILENAME = "dataset_info.json"

# Configuración de logging (estándares del dominio)
LOG_EMOJIS = {
    "download": "📥",
    "success": "✅",
    "warning": "⚠️",
    "error": "❌",
    "loading": "📊",
    "saving": "💾",
    "info": "ℹ️"
}
