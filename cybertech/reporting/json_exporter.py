"""
JSON Forensic Exporter for Cyber Tech
"""

import json
from typing import Dict, Any

def export_to_json(report_data: Dict[str, Any], output_path: str):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
