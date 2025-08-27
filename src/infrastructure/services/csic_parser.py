from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import List, Optional

from ...domain.entities.log_entry import LogEntry


_LINE_RE = re.compile(r"^(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<status>\d{3}).*$")


def _to_int(value: Optional[str], default: int = 200) -> int:
    try:
        if value is None:
            return default
        return int(str(value).strip())
    except Exception:
        return default


def _to_float_ms(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    try:
        v = float(str(value).strip())
        # Heuristic: if it's clearly seconds (< 1000), convert to ms; if already ms, keep
        return v * 1000.0 if v < 1000 else v
    except Exception:
        return None


def _get_first_present(row: dict, keys: List[str]) -> Optional[str]:
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return str(row[k])
    return None


def _parse_csv_files(root_dir: str, entries: List[LogEntry]) -> None:
    for csv_path in Path(root_dir).rglob("*.csv"):
        try:
            with open(csv_path, "r", encoding="utf-8", errors="ignore") as fh:
                reader = csv.DictReader(fh)
                # Normalize headers to lowercase for flexible matching
                if reader.fieldnames is None:
                    continue
                field_map = {name: name for name in reader.fieldnames}
                for row in reader:
                    # Lowercase-view of keys without losing original values
                    lowered = {k.lower(): v for k, v in row.items()}

                    method = _get_first_present(lowered, [
                        "method", "request_method", "http_method",
                    ]) or "GET"

                    path = _get_first_present(lowered, [
                        "path", "url", "request_uri", "uri", "endpoint",
                    ]) or "/"

                    status_str = _get_first_present(lowered, [
                        "status", "status_code", "response_code",
                    ])
                    status = _to_int(status_str, default=200)

                    timestamp = _get_first_present(lowered, [
                        "timestamp", "time", "date", "datetime",
                    ]) or ""

                    user_agent = _get_first_present(lowered, [
                        "user_agent", "ua", "agent",
                    ])

                    rt = _get_first_present(lowered, [
                        "response_time_ms", "response_time", "latency", "rt",
                    ])
                    response_time_ms = _to_float_ms(rt)

                    entries.append(
                        LogEntry(
                            timestamp=timestamp,
                            ip="0.0.0.0",
                            method=method,
                            path=path,
                            status=status,
                            user_agent=user_agent,
                            response_time_ms=response_time_ms,
                        )
                    )
        except Exception:
            continue


def _parse_txt_files(root_dir: str, entries: List[LogEntry]) -> None:
    for txt_path in Path(root_dir).rglob("*.txt"):
        try:
            with open(txt_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    m = _LINE_RE.match(line)
                    if not m:
                        continue
                    method = m.group("method")
                    url_path = m.group("path")
                    status_str = m.group("status")
                    status = _to_int(status_str, default=200)
                    entries.append(
                        LogEntry(
                            timestamp="",
                            ip="0.0.0.0",
                            method=method,
                            path=url_path,
                            status=status,
                            user_agent=None,
                            response_time_ms=None,
                        )
                    )
        except Exception:
            continue


def parse_csic_files(root_dir: str) -> List[LogEntry]:
    """Parse CSIC 2010 dataset files (CSV or TXT) into LogEntry list."""
    entries: List[LogEntry] = []
    _parse_csv_files(root_dir, entries)
    _parse_txt_files(root_dir, entries)
    return entries

