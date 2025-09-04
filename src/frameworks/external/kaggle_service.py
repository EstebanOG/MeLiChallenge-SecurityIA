from pathlib import Path
from typing import Optional

import shutil
import kagglehub


def download_and_extract_dataset(dataset: str, dest_dir: Optional[str] = None) -> str:
    try:
        dataset_path = kagglehub.dataset_download(dataset)
        src_path = Path(dataset_path)
        
        if not src_path.exists():
            raise FileNotFoundError(f"No se pudo encontrar el dataset en {src_path}")

        if dest_dir:
            dest_path = Path(dest_dir)
            target_path = dest_path / src_path.name
            if target_path.exists():
                shutil.rmtree(target_path)
            shutil.copytree(src_path, target_path)
            return str(target_path)
        return dataset_path
        
    except Exception as e:
        raise Exception(f"Error al descargar dataset '{dataset}': {str(e)}")
