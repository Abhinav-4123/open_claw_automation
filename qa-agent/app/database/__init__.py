"""
NEXUS QA - Database Module
SQLite-based persistent storage for scans, journeys, and recommendations.
"""

from .db import Database, get_db
from .models import (
    ScanRecord,
    CheckResultRecord,
    RecommendationRecord,
    JourneyRecord,
    ClarificationRecord,
)

__all__ = [
    'Database',
    'get_db',
    'ScanRecord',
    'CheckResultRecord',
    'RecommendationRecord',
    'JourneyRecord',
    'ClarificationRecord',
]
