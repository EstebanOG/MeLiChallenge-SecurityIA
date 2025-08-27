from typing import List, Optional
from fastapi import APIRouter
from pydantic import BaseModel, Field
from ...domain.entities.log_entry import LogEntry
from ...infrastructure.detectors.ml_isolation_forest_detector import IsolationForestDetector
from ...infrastructure.services.kaggle_service import download_and_extract_dataset
from ...infrastructure.services.csic_parser import parse_csic_files
from ...application.use_cases.analyze_logs import AnalyzeLogsUseCase


router = APIRouter()


class LogItem(BaseModel):
    timestamp: str
    ip: str
    method: str
    path: str
    status: int
    user_agent: Optional[str] = None
    response_time_ms: Optional[float] = Field(default=None, ge=0)


class AnalyzeRequest(BaseModel):
    logs: List[LogItem]


class AnalyzeResponseModel(BaseModel):
    is_threat: bool
    suggested_action: str
    score: float


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/analyze", response_model=AnalyzeResponseModel)
def analyze_batch(req: AnalyzeRequest):
    logs: List[LogEntry] = [
        LogEntry(
            timestamp=item.timestamp,
            ip=item.ip,
            method=item.method,
            path=item.path,
            status=item.status,
            user_agent=item.user_agent,
            response_time_ms=item.response_time_ms,
        )
        for item in req.logs
    ]

    detector = IsolationForestDetector()
    use_case = AnalyzeLogsUseCase(detector=detector)
    result = use_case.execute(logs)
    return result


@router.post("/train")
def train_model(req: AnalyzeRequest):
    logs: List[LogEntry] = [
        LogEntry(
            timestamp=item.timestamp,
            ip=item.ip,
            method=item.method,
            path=item.path,
            status=item.status,
            user_agent=item.user_agent,
            response_time_ms=item.response_time_ms,
        )
        for item in req.logs
    ]

    detector = IsolationForestDetector()
    detector.fit(logs)
    return {"status": "trained", "samples": len(logs)}


@router.post("/train/kaggle")
def train_model_from_kaggle():
    dataset = "ispangler/csic-2010-web-application-attacks"
    dest_dir = "data/raw"
    extract_dir = download_and_extract_dataset(dataset, dest_dir)
    logs = parse_csic_files(extract_dir)
    detector = IsolationForestDetector()
    detector.fit(logs)
    return {"status": "trained", "samples": len(logs), "dataset": dataset}


