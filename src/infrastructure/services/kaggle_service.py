from __future__ import annotations

import os
import shutil
from pathlib import Path
import kagglehub

def download_and_extract_dataset(dataset: str, dest_dir: str) -> str:
    """Download a Kaggle dataset using kagglehub and return local directory path.

    Args:
        dataset: e.g., "ispangler/csic-2010-web-application-attacks".
        dest_dir: kept for signature compatibility; ignored (kagglehub manages cache).

    Returns:
        The path to the local dataset directory managed by kagglehub.
    """
    path = kagglehub.dataset_download(dataset)
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(f"Dataset not found locally at {path}")

    # Mirror into dest_dir for a stable, project-local path
    dest_root = Path(dest_dir)
    dest_root.mkdir(parents=True, exist_ok=True)
    target = dest_root / src.name
    if target.exists():
        # best-effort update: copytree with dirs_exist_ok keeps existing files
        shutil.copytree(src, target, dirs_exist_ok=True)
    else:
        shutil.copytree(src, target)

    return str(target)

