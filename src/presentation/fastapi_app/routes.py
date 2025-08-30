from typing import List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from ...domain.entities.log_entry import LogEntry
from ...infrastructure.detectors.ml_isolation_forest_detector import IsolationForestDetector
from ...infrastructure.services.iot_dataset_service import IoTDatasetService
from ...orchestration.langgraph.graph import run_agents_pipeline
import pandas as pd
from pathlib import Path

router = APIRouter()

# Instancia del servicio de datasets
iot_service = IoTDatasetService()

# ============================================================================
# MODELOS DE DATOS PARA IoT
# ============================================================================

class IoTLogItem(BaseModel):
    timestamp: str
    device_id: str
    device_type: str
    cpu_usage: float = Field(ge=0, le=100)
    memory_usage: float = Field(ge=0, le=100)
    network_in_kb: int = Field(ge=0)
    network_out_kb: int = Field(ge=0)
    packet_rate: int = Field(ge=0)
    avg_response_time_ms: float = Field(ge=0)
    service_access_count: int = Field(ge=0)
    failed_auth_attempts: int = Field(ge=0)
    is_encrypted: int = Field(ge=0, le=1)
    geo_location_variation: float = Field(ge=0)
    label: Optional[str] = None

class IoTAnalyzeRequest(BaseModel):
    logs: List[IoTLogItem]

class IoTAnalyzeResponse(BaseModel):
    trace_id: str
    score: float
    decision: dict
    batch_size: int

class TrainResponse(BaseModel):
    status: str
    samples: int
    file_path: str  # Cambiado de model_file_path para evitar conflicto con Pydantic
    features: int

class DatasetInfo(BaseModel):
    total_rows: int
    labeled_rows: int
    unlabeled_rows: int
    columns: List[str]
    label_distribution: dict
    device_type_distribution: dict
    anomaly_ratio: float

# ============================================================================
# ENDPOINTS DE SALUD Y INFORMACIÓN
# ============================================================================

@router.get("/health")
def health():
    return {"status": "ok", "dataset": "IoT Anomaly Detection"}

@router.get("/")
def get_info():
    """Obtiene información sobre el proyecto y el modelo."""
    return {
        "project": "IoT Anomaly Detection API",
        "version": "2.0.0",
        "description": "API para detección de anomalías en dispositivos IoT",
        "features": [
            "Detección de anomalías en tiempo real",
            "Análisis de métricas de dispositivos IoT",
            "Modelo Isolation Forest adaptado",
            "Pipeline de agentes LangGraph"
        ],
        "supported_device_types": [
            "thermostat", "smart", "sensor", "camera", 
            "lock", "hub", "appliance", "wearable"
        ]
    }

# ============================================================================
# ENDPOINTS DE ANÁLISIS
# ============================================================================

@router.post("/analyze", response_model=IoTAnalyzeResponse)
def analyze_iot_batch(req: IoTAnalyzeRequest):
    """
    Analiza un lote de logs de dispositivos IoT para detectar anomalías.
    
    Args:
        req: Lista de logs de dispositivos IoT
        
    Returns:
        Resultado del análisis con score y decisión
    """
    try:
        # Convertir a formato raw para el pipeline
        raw_logs = [item.model_dump() for item in req.logs]
        
        # Ejecutar pipeline de agentes
        result = run_agents_pipeline(raw_logs)
        
        return IoTAnalyzeResponse(
            trace_id=result["trace_id"],
            score=result["score"],
            decision=result["decision"],
            batch_size=len(req.logs)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en análisis: {str(e)}")

# ============================================================================
# ENDPOINTS DE ENTRENAMIENTO
# ============================================================================

@router.post("/train/iot", response_model=TrainResponse)
def train_iot_model(req: IoTAnalyzeRequest):
    """
    Entrena el modelo con datos de dispositivos IoT proporcionados.
    
    Args:
        req: Lista de logs de dispositivos IoT para entrenamiento
        
    Returns:
        Estado del entrenamiento
    """
    try:
        # Convertir a LogEntry
        logs: List[LogEntry] = [
            LogEntry(
                timestamp=item.timestamp,
                device_id=item.device_id,
                device_type=item.device_type,
                cpu_usage=item.cpu_usage,
                memory_usage=item.memory_usage,
                network_in_kb=item.network_in_kb,
                network_out_kb=item.network_out_kb,
                packet_rate=item.packet_rate,
                avg_response_time_ms=item.avg_response_time_ms,
                service_access_count=item.service_access_count,
                failed_auth_attempts=item.failed_auth_attempts,
                is_encrypted=item.is_encrypted,
                geo_location_variation=item.geo_location_variation,
                label=item.label,
            )
            for item in req.logs
        ]

        # Entrenar modelo
        detector = IsolationForestDetector()
        detector.fit(logs)
        
        return TrainResponse(
            status="trained",
            samples=len(logs),
            file_path="models/isoforest.joblib",
            features=11  # Número de features del modelo IoT
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en entrenamiento: {str(e)}")

@router.post("/train/iot/kaggle", response_model=TrainResponse)
def train_iot_model_from_kaggle():
    """
    Descarga el dataset de IoT desde Kaggle y entrena el modelo.
    
    Returns:
        Estado del entrenamiento con información del dataset
    """
    try:
        # Descargar dataset
        print("📥 Descargando dataset de IoT desde Kaggle...")
        dataset_path = iot_service.download_dataset()
        
        # Cargar datos
        print("📊 Cargando dataset...")
        df = iot_service.load_dataset(dataset_path)
        
        # Split del dataset
        print("✂️ Dividiendo dataset...")
        labeled_df, unlabeled_df = iot_service.split_dataset(df, labeled_ratio=0.2)
        
        # Guardar datasets procesados
        print("💾 Guardando datasets procesados...")
        iot_service.save_datasets(labeled_df, unlabeled_df)
        
        # Convertir a LogEntry para entrenamiento
        print("🤖 Entrenando modelo...")
        logs: List[LogEntry] = []
        
        # Usar datos etiquetados para entrenamiento
        if not labeled_df.empty:
            for _, row in labeled_df.iterrows():
                log_entry = LogEntry(
                    timestamp=str(row['timestamp']),
                    device_id=str(row['device_id']),
                    device_type=str(row['device_type']),
                    cpu_usage=float(row['cpu_usage']),
                    memory_usage=float(row['memory_usage']),
                    network_in_kb=int(row['network_in_kb']),
                    network_out_kb=int(row['network_out_kb']),
                    packet_rate=int(row['packet_rate']),
                    avg_response_time_ms=float(row['avg_response_time_ms']),
                    service_access_count=int(row['service_access_count']),
                    failed_auth_attempts=int(row['failed_auth_attempts']),
                    is_encrypted=int(row['is_encrypted']),
                    geo_location_variation=float(row['geo_location_variation']),
                    label=str(row['label']) if pd.notna(row['label']) else None,
                )
                logs.append(log_entry)
        
        # Entrenar modelo
        detector = IsolationForestDetector()
        detector.fit(logs)
        
        return TrainResponse(
            status="trained_from_kaggle",
            samples=len(logs),
            file_path="models/isoforest.joblib",
            features=11
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en entrenamiento desde Kaggle: {str(e)}")

# ============================================================================
# ENDPOINTS DE DATASET
# ============================================================================

@router.get("/dataset/info", response_model=DatasetInfo)
def get_dataset_info():
    """
    Obtiene información sobre el dataset procesado.
    
    Returns:
        Información del dataset incluyendo distribución de clases
    """
    try:
        processed_dir = Path("data/processed")
        info_file = processed_dir / "dataset_info.json"
        
        if not info_file.exists():
            raise HTTPException(
                status_code=404, 
                detail="Dataset no encontrado. Ejecuta /train/iot/kaggle primero."
            )
        
        import json
        with open(info_file, 'r') as f:
            info = json.load(f)
        
        return DatasetInfo(**info)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo información del dataset: {str(e)}")

@router.get("/dataset/sample")
def get_dataset_sample(size: int = 10):
    """
    Obtiene una muestra del dataset para pruebas.
    
    Args:
        size: Tamaño de la muestra (máximo 100)
        
    Returns:
        Muestra del dataset
    """
    try:
        size = min(size, 100)  # Limitar tamaño máximo
        
        processed_dir = Path("data/processed")
        complete_file = processed_dir / "dataset_complete.csv"
        
        if not complete_file.exists():
            raise HTTPException(
                status_code=404, 
                detail="Dataset no encontrado. Ejecuta /train/iot/kaggle primero."
            )
        
        df = pd.read_csv(complete_file)
        sample = df.sample(n=size, random_state=42)
        
        return {
            "sample_size": len(sample),
            "total_rows": len(df),
            "data": sample.to_dict('records')
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo muestra: {str(e)}")


