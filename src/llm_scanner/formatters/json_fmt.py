"""JSON output formatter."""
from __future__ import annotations
import json
from datetime import datetime, timezone

from llm_scanner import __version__
from llm_scanner.scanner import ScanResult


def format_json(result: ScanResult) -> str:
    """Serialize scan results to JSON string."""
    output = {
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "total_findings": len(result.active_findings),
            "duration_seconds": round(result.duration_seconds, 3),
            "by_severity": result.counts_by_severity(),
            "by_category": result.counts_by_category(),
        },
        "findings": [f.to_dict() for f in result.active_findings],
    }
    return json.dumps(output, indent=2, default=str)
