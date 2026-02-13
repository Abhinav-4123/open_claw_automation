"""
NEXUS QA - Journey Detection Module
Auto-detect and map user journeys from web applications.
"""

from .detector import JourneyDetector, detect_journeys
from .mapper import JourneyMapper, JOURNEY_TEMPLATES

__all__ = [
    'JourneyDetector',
    'detect_journeys',
    'JourneyMapper',
    'JOURNEY_TEMPLATES',
]
