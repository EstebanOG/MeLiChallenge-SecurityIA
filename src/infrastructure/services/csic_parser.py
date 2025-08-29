from __future__ import annotations

import re
from pathlib import Path
from typing import List

from ...domain.entities.log_entry import LogEntry


_LINE_RE = re.compile(r"^(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<status>\d{3}).*$")


def parse_csic_files(root_dir: str) -> List[LogEntry]:
    """Parse CSIC 2010 dataset text files into LogEntry list.

    Simplified parsing: extracts method, path, status when present.
    Missing fields are filled with defaults.
    """
    entries: List[LogEntry] = []
    for path in Path(root_dir).rglob("*.txt"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
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
                    status = int(status_str) if status_str.isdigit() else 200
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
    return entries

