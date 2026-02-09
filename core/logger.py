"""
Decision Logger - Records all decisions for transparency and learning
"""
import os
import json
from datetime import datetime
from typing import List
from dataclasses import asdict

from .brain import Decision


class DecisionLogger:
    """Logs all decisions to file for transparency"""

    def __init__(self):
        self.log_dir = os.getenv("LOG_DIR", "/var/log/openclaw")
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, "decisions.jsonl")

    def log(self, decision: Decision):
        """Log a decision to file"""
        entry = {
            **asdict(decision),
            "timestamp": decision.timestamp.isoformat(),
            "type": decision.type.value
        }

        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def get_recent(self, count: int = 50) -> List[dict]:
        """Get recent decisions"""
        decisions = []

        try:
            with open(self.log_file, "r") as f:
                lines = f.readlines()[-count:]
                for line in lines:
                    decisions.append(json.loads(line))
        except FileNotFoundError:
            pass

        return decisions

    def get_by_type(self, decision_type: str) -> List[dict]:
        """Get decisions of a specific type"""
        decisions = []

        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    d = json.loads(line)
                    if d.get("type") == decision_type:
                        decisions.append(d)
        except FileNotFoundError:
            pass

        return decisions

    def get_success_rate(self) -> float:
        """Calculate overall success rate"""
        decisions = self.get_recent(100)
        if not decisions:
            return 0.0

        successful = sum(1 for d in decisions if d.get("success"))
        return successful / len(decisions)
