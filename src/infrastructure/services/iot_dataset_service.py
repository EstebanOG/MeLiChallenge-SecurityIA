from __future__ import annotations

import os
import shutil
from pathlib import Path
import kagglehub
import pandas as pd
from typing import Tuple, Optional

def download_iot_dataset(dataset_name: str = "ziya07/anomaly-detection-and-threat-intelligence-dataset") -> str:
    """Download the IoT anomaly detection dataset from Kaggle.
    
    Args:
        dataset_name: Kaggle dataset identifier
        
    Returns:
        Path to the local dataset directory
    """
    try:
        # Download using kagglehub
        dataset_path = kagglehub.dataset_download(dataset_name)
        src = Path(dataset_path)
        
        if not src.exists():
            raise FileNotFoundError(f"Dataset not found at {src}")
            
        # Copy to project data directory
        project_data_dir = Path(__file__).parent.parent.parent.parent / "data" / "raw"
        project_data_dir.mkdir(parents=True, exist_ok=True)
        
        target = project_data_dir / "iot_anomaly_dataset"
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(src, target)
        
        print(f"✅ Dataset downloaded and saved to: {target}")
        return str(target)
        
    except Exception as e:
        print(f"❌ Error downloading dataset: {e}")
        raise

def load_iot_dataset(data_dir: str) -> pd.DataFrame:
    """Load the IoT dataset from the specified directory.
    
    Args:
        data_dir: Path to the dataset directory
        
    Returns:
        Loaded DataFrame
    """
    data_path = Path(data_dir)
    csv_files = list(data_path.rglob("*.csv"))
    
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    
    # Load the first CSV file found
    data_file = csv_files[0]
    print(f"📊 Loading file: {data_file.name}")
    
    df = pd.read_csv(data_file)
    print(f"✅ Dataset loaded successfully: {df.shape[0]} rows × {df.shape[1]} columns")
    
    return df

def split_dataset(df: pd.DataFrame, labeled_ratio: float = 0.2) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Split the dataset into labeled and unlabeled portions.
    
    Args:
        df: Input DataFrame
        labeled_ratio: Proportion of data to keep labeled (default: 0.2)
        
    Returns:
        Tuple of (labeled_df, unlabeled_df)
    """
    # Check if label column exists
    if 'label' not in df.columns:
        print("⚠️ No 'label' column found. Treating all data as unlabeled.")
        return pd.DataFrame(), df.copy()
    
    # Split based on label availability
    labeled_mask = df['label'].notna() & (df['label'] != '')
    labeled_df = df[labeled_mask].copy()
    unlabeled_df = df[~labeled_mask].copy()
    
    # If we have more labeled data than requested, sample it
    if len(labeled_df) > int(len(df) * labeled_ratio):
        labeled_df = labeled_df.sample(n=int(len(df) * labeled_ratio), random_state=42)
    
    print(f"📊 Dataset split:")
    print(f"   Labeled: {len(labeled_df)} rows ({len(labeled_df)/len(df)*100:.1f}%)")
    print(f"   Unlabeled: {len(unlabeled_df)} rows ({len(unlabeled_df)/len(df)*100:.1f}%)")
    
    return labeled_df, unlabeled_df

def save_processed_datasets(labeled_df: pd.DataFrame, unlabeled_df: pd.DataFrame, 
                           output_dir: str = "data/processed") -> None:
    """Save the processed datasets to the specified directory.
    
    Args:
        labeled_df: Labeled portion of the dataset
        unlabeled_df: Unlabeled portion of the dataset
        output_dir: Output directory path
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Save datasets
    if not labeled_df.empty:
        labeled_path = output_path / "dataset_labeled_20p.csv"
        labeled_df.to_csv(labeled_path, index=False)
        print(f"💾 Saved labeled dataset: {labeled_path}")
    
    if not unlabeled_df.empty:
        unlabeled_path = output_path / "dataset_unlabeled_80p.csv"
        unlabeled_df.to_csv(unlabeled_path, index=False)
        print(f"💾 Saved unlabeled dataset: {unlabeled_path}")
    
    # Save complete dataset
    complete_df = pd.concat([labeled_df, unlabeled_df], ignore_index=True)
    complete_path = output_path / "dataset_complete.csv"
    complete_df.to_csv(complete_path, index=False)
    print(f"💾 Saved complete dataset: {complete_path}")
    
    # Save dataset info
    info = {
        "total_rows": len(complete_df),
        "labeled_rows": len(labeled_df),
        "unlabeled_rows": len(unlabeled_df),
        "columns": list(complete_df.columns),
        "label_distribution": labeled_df['label'].value_counts().to_dict() if not labeled_df.empty else {},
        "device_type_distribution": complete_df['device_type'].value_counts().to_dict(),
        "anomaly_ratio": len(labeled_df[labeled_df['label'] != 'Normal']) / len(labeled_df) if not labeled_df.empty else 0
    }
    
    import json
    info_path = output_path / "dataset_info.json"
    with open(info_path, 'w') as f:
        json.dump(info, f, indent=2)
    print(f"💾 Saved dataset info: {info_path}")
