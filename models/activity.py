# models/activity.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class UserActivity(db.Model):
    __tablename__ = 'user_activity'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), nullable=False)  # EMP_001 type
    username = db.Column(db.String(100))
    activity_type = db.Column(db.String(50), nullable=False)  # login, file_access, etc.
    action = db.Column(db.String(50))  # LOGIN, FILE_READ, etc. (data_generator se match)
    resource = db.Column(db.String(200))  # file path
    ip_address = db.Column(db.String(50))
    status = db.Column(db.String(20))  # normal, suspicious, failed
    files_accessed = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Float, default=0.0)
    activity_details = db.Column(db.Text)  # JSON data
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Activity {self.activity_type} - Risk: {self.risk_score}>'
    
    def to_dict(self):
        """Convert to dictionary for JSON response"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'activity_type': self.activity_type,
            'action': self.action,
            'resource': self.resource,
            'ip_address': self.ip_address,
            'status': self.status,
            'files_accessed': self.files_accessed,
            'risk_score': self.risk_score,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'activity_details': json.loads(self.activity_details) if self.activity_details else {}
        }