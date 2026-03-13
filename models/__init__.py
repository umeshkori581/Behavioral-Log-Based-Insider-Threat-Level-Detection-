# Models package for ThreatGuard AI (anomaly detection, risk engine, data generator)

# models/__init__.py
from .anomaly_detector import AnomalyDetector
from .data_generator import DataGenerator
from .risk_engine import RiskEngine, AlertManager

# Database ke liye
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

# UserActivity table ko import karo (abhi nahi hai, agle step mein banayenge)
from .activity import UserActivity