import pandas as pd
from pathlib import Path
from typing import Dict, Any

from ..entities.dataset_config import LOG_EMOJIS


def find_csv_files(data_dir: str) -> list[Path]:
    data_path = Path(data_dir)
    csv_files = list(data_path.rglob("*.csv"))
    
    if not csv_files:
        raise FileNotFoundError(f"No se encontraron archivos CSV en {data_dir}")
    
    return csv_files


def load_csv_file(file_path: Path) -> pd.DataFrame:
    """
    Carga un archivo CSV en un DataFrame.
    
    Args:
        file_path: Ruta al archivo CSV
        
    Returns:
        DataFrame con los datos cargados
        
    Raises:
        ValueError: Si el archivo está vacío o corrupto
    """
    df = pd.read_csv(file_path)
    
    if df.empty:
        raise ValueError(f"El archivo {file_path} está vacío")
    
    return df


def create_labeled_mask(df: pd.DataFrame) -> pd.Series:
    """
    Crea una máscara para identificar datos etiquetados.
    
    Args:
        df: DataFrame con los datos
        
    Returns:
        Serie booleana indicando qué filas están etiquetadas
    """
    if 'label' not in df.columns:
        return pd.Series([False] * len(df), index=df.index)
    
    return df['label'].notna() & (df['label'] != '')


def calculate_dataset_stats(df: pd.DataFrame, labeled_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calcula estadísticas del dataset.
    
    Args:
        df: DataFrame completo
        labeled_df: DataFrame con datos etiquetados
        
    Returns:
        Diccionario con estadísticas del dataset
    """
    return {
        "total_rows": len(df),
        "labeled_rows": len(labeled_df),
        "unlabeled_rows": len(df) - len(labeled_df),
        "columns": list(df.columns),
        "label_distribution": _get_label_distribution(labeled_df),
        "device_type_distribution": df['device_type'].value_counts().to_dict(),
        "anomaly_ratio": _calculate_anomaly_ratio(labeled_df)
    }


def _get_label_distribution(labeled_df: pd.DataFrame) -> Dict[str, int]:
    """Obtiene la distribución de etiquetas."""
    if labeled_df.empty or 'label' not in labeled_df.columns:
        return {}
    return labeled_df['label'].value_counts().to_dict()


def _calculate_anomaly_ratio(labeled_df: pd.DataFrame) -> float:
    """Calcula la proporción de anomalías."""
    if labeled_df.empty or 'label' not in labeled_df.columns:
        return 0.0
    
    anomaly_count = len(labeled_df[labeled_df['label'] != 'Normal'])
    return anomaly_count / len(labeled_df) if len(labeled_df) > 0 else 0.0


def log_dataset_info(message: str, emoji_type: str = "info") -> None:
    """
    Registra información del dataset con emoji apropiado.
    
    Args:
        message: Mensaje a mostrar
        emoji_type: Tipo de emoji a usar
    """
    emoji = LOG_EMOJIS.get(emoji_type, LOG_EMOJIS["info"])
    print(f"{emoji} {message}")


def log_split_info(labeled_df: pd.DataFrame, unlabeled_df: pd.DataFrame, total_df: pd.DataFrame) -> None:
    """Registra información sobre la división del dataset."""
    log_dataset_info("División del dataset:", "info")
    print(f"   Etiquetado: {len(labeled_df)} filas ({len(labeled_df)/len(total_df)*100:.1f}%)")
    print(f"   No etiquetado: {len(unlabeled_df)} filas ({len(unlabeled_df)/len(total_df)*100:.1f}%)")
