from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class LogEntry:
    # Campos del dataset de threat intelligence
    session_id: str
    network_packet_size: int
    protocol_type: str
    login_attempts: int
    session_duration: float
    encryption_used: str
    ip_reputation_score: float
    failed_logins: int
    browser_type: str
    unusual_time_access: bool
    attack_detected: bool
    # Campo opcional para el label (puede no estar presente en datos sin etiquetar)
    label: Optional[str] = None


