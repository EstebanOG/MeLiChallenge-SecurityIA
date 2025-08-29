from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class LogEntry:
    # Campos del nuevo dataset de IoT/smart systems
    timestamp: str
    device_id: str
    device_type: str
    cpu_usage: float
    memory_usage: float
    network_in_kb: int
    network_out_kb: int
    packet_rate: int
    avg_response_time_ms: float
    service_access_count: int
    failed_auth_attempts: int
    is_encrypted: int
    geo_location_variation: float
    # Campo opcional para el label (puede no estar presente en datos sin etiquetar)
    label: Optional[str] = None


