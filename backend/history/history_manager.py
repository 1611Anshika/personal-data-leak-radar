import json
import os
from datetime import datetime

HISTORY_FILE = "scan_history.json"


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception:
        return []


def save_history(record):
    history = load_history()

    history.insert(0, record)

    # Keep latest 50 scans
    history = history[:50]

    with open(
        HISTORY_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            history,
            file,
            indent=4
        )


def create_scan_record(
    filename,
    findings,
    risk,
    verification=None
):

    record = {
        "id": datetime.now().strftime(
            "%Y%m%d%H%M%S%f"
        ),

        "filename": filename,

        "timestamp": datetime.now().isoformat(),

        "findings": len(findings),

        "risk": risk.get(
            "level",
            "LOW"
        ),

        "risk_score": risk.get(
            "score",
            0
        ),

        "protected": (
            verification is not None
        ),

        "verified": (
            verification.get(
                "verified",
                False
            )
            if verification
            else False
        )
    }

    save_history(record)

    return record