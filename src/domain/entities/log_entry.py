from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class LogEntry:
    timestamp: str
    ip: str
    method: str
    path: str
    status: int
    user_agent: Optional[str] = None
    response_time_ms: Optional[float] = None


