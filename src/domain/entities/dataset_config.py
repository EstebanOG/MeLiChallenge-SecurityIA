"""
Configuración del dominio para dataset de detección de intrusiones de ciberseguridad.

Este archivo contiene las entidades y configuraciones del dominio
relacionadas con la gestión de datasets, no detalles de infraestructura.
"""

from pathlib import Path

# Directorios de datos
DATA_DIR = Path("data")
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"

# Dataset
DEFAULT_DATASET = "dnkumars/cybersecurity-intrusion-detection-dataset"

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
