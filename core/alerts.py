# Alert system for logging and displaying detected threats in the IDS.
# Written by: @dukebismaya

import json
import os
import logging
from datetime import datetime

logger = logging.getLogger("PySentry.alerts")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOG_PATH = os.path.join(BASE_DIR, "logs", "ids_alerts.log")


class AlertSystem:
    def __init__(self, log_file=DEFAULT_LOG_PATH):
        if log_file is None:
            current_file_path = os.path.abspath(__file__)
            core_dir = os.path.dirname(current_file_path)
            project_root = os.path.dirname(core_dir)
            self.log_file = os.path.join(project_root, "logs", "ids_alerts.log")
        else:
            self.log_file = log_file
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

        # Do NOT truncate logs on startup — preserve forensic evidence.
        logger.info("Alert system initialized. Logging to: %s", self.log_file)

    def generate_alert(self, threat, packet_info):
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threat_type": threat["type"],
            "rule_or_score": threat.get("rule", round(threat.get("score", 0), 2)),
            "source_ip": packet_info["source_ip"],
            "destination_ip": packet_info["destination_ip"],
        }
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(alert) + "\n")
        except OSError:
            logger.exception("Failed to write alert to log file.")

        logger.warning(
            "ALERT: %s detected from %s → %s (confidence: %.2f)",
            alert["threat_type"],
            alert["source_ip"],
            alert["destination_ip"],
            threat.get("confidence", 0),
        )
