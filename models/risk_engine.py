"""
Risk Scoring Engine
Converts anomaly scores + contextual factors into a 0–100 risk score
"""


class RiskEngine:
    THRESHOLDS = {"HIGH": 65, "MEDIUM": 35, "LOW": 0}

    def calculate(self, anomaly_score: float, features_tuple) -> tuple:
        """
        Compute final risk score 0–100 from anomaly score + feature context.
        Returns (score: float, level: str)
        """
        features, _ = features_tuple

        # Base from anomaly model (0–1 → 0–70 points)
        base = anomaly_score * 70

        # Bonus points from contextual signals
        bonus = 0
        if features["failed_logins"] > 5:    bonus += 15
        elif features["failed_logins"] > 2:  bonus += 7
        if features["off_hours_events"] > 3: bonus += 10
        if features["bulk_access_count"] > 0: bonus += 8
        if features["unknown_ips"] > 0:       bonus += 12
        if features["suspicious_events"] > 2: bonus += 15
        elif features["suspicious_events"] > 0: bonus += 8

        score = round(min(base + bonus, 100), 1)

        if score >= self.THRESHOLDS["HIGH"]:
            level = "HIGH"
        elif score >= self.THRESHOLDS["MEDIUM"]:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level


"""
Alert Manager
Generates structured security alerts when anomalous behavior detected
"""


class AlertManager:
    ALERT_TYPES = {
        "BULK_FILE_ACCESS": "Bulk File Access Detected",
        "OFF_HOURS":        "Off-Hours System Access",
        "FAILED_LOGIN":     "Repeated Login Failures",
        "UNKNOWN_IP":       "Access from Unknown IP",
        "DATA_EXFIL":       "Potential Data Exfiltration",
        "ANOMALY":          "Behavioral Anomaly Detected"
    }

    def generate(self, user_id: str, features_tuple, risk_score: float, level: str) -> dict:
        features, _ = features_tuple

        # Determine primary alert type
        if features["bulk_access_count"] > 1:
            atype = "BULK_FILE_ACCESS"
        elif features["failed_logins"] > 5:
            atype = "FAILED_LOGIN"
        elif features["off_hours_events"] > 3:
            atype = "OFF_HOURS"
        elif features["unknown_ips"] > 0:
            atype = "UNKNOWN_IP"
        else:
            atype = "ANOMALY"

        files = features["total_files_accessed"]
        baseline = 100  # fixed reference

        message = (
            f"ALERT: {self.ALERT_TYPES[atype]} | "
            f"User: {user_id} | "
            f"Files Accessed: {files} (Baseline: {baseline}) | "
            f"Risk Level: {level}"
        )

        return {
            "user_id": user_id,
            "type": atype,
            "severity": level,
            "message": message,
            "details": {
                "files_accessed": files,
                "baseline": baseline,
                "ratio": round(files / max(baseline, 1), 2),
                "failed_logins": features["failed_logins"],
                "off_hours": features["off_hours_events"],
                "unknown_ips": features["unknown_ips"],
                "risk_score": risk_score
            }
        }

# risk_engine.py ke end mein ye add karo

import json
from datetime import datetime, timedelta
import math

class RealTimeTracker:
    """Real-time activity tracking and risk calculation"""
    
    def __init__(self, db_session):
        self.db = db_session
        from .activity import UserActivity
        self.UserActivity = UserActivity
    
    def track_activity(self, user_id, username, action, resource=None, 
                       ip_address=None, status="normal", files_accessed=0):
        """
        Track user activity in real-time
        """
        # Activity type determine karo
        activity_type = self._get_activity_type(action)
        
        # Risk score calculate karo
        risk_score = self._calculate_risk_score(
            user_id, action, files_accessed, status
        )
        
        # Activity details banao
        details = {
            'action': action,
            'resource': resource,
            'files_accessed': files_accessed,
            'status': status
        }
        
        # Database mein save karo
        activity = self.UserActivity(
            user_id=user_id,
            username=username,
            activity_type=activity_type,
            action=action,
            resource=resource,
            ip_address=ip_address or "127.0.0.1",
            status=status,
            files_accessed=files_accessed,
            risk_score=risk_score,
            activity_details=json.dumps(details),
            timestamp=datetime.utcnow()
        )
        
        self.db.session.add(activity)
        self.db.session.commit()
        
        # Update user's overall risk score
        self._update_user_risk(user_id)
        
        return {
            'activity_id': activity.id,
            'risk_score': risk_score,
            'timestamp': activity.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def _get_activity_type(self, action):
        """Map action to activity type"""
        if 'LOGIN' in action:
            return 'login'
        elif 'FILE' in action:
            return 'file_access'
        elif 'DOWNLOAD' in action:
            return 'download'
        elif 'USB' in action:
            return 'usb_activity'
        elif 'EMAIL' in action:
            return 'email'
        else:
            return 'other'
    
    def _calculate_risk_score(self, user_id, action, files_accessed, status):
        """Calculate risk score for this activity"""
        risk = 0.0
        
        # Failed login
        if action == "LOGIN_FAILED":
            risk += 0.3
            # Check recent failures
            recent = self.get_recent_activities(user_id, minutes=5)
            if recent > 3:
                risk += 0.4
        
        # Bulk file access
        if files_accessed > 100:
            risk += 0.4
        elif files_accessed > 50:
            risk += 0.2
        
        # Suspicious status
        if status == "suspicious":
            risk += 0.3
        
        # Off-hours check
        current_hour = datetime.now().hour
        if current_hour < 7 or current_hour > 20:
            risk += 0.2
        
        return min(risk, 1.0)  # Max 1.0
    
    def get_recent_activities(self, user_id, minutes=5):
        """Get count of recent activities"""
        recent = self.UserActivity.query.filter_by(user_id=user_id)\
            .filter(self.UserActivity.timestamp >= datetime.utcnow() - timedelta(minutes=minutes))\
            .count()
        return recent
    
    def _update_user_risk(self, user_id):
        """Update user's overall risk score based on recent activities"""
        # Last 24 hours activities
        last_24h = self.UserActivity.query.filter_by(user_id=user_id)\
            .filter(self.UserActivity.timestamp >= datetime.utcnow() - timedelta(hours=24))\
            .all()
        
        if not last_24h:
            return
        
        # Weighted average (recent activities ka weight zyada)
        total_weight = 0
        weighted_sum = 0
        
        for activity in last_24h:
            hours_ago = (datetime.utcnow() - activity.timestamp).seconds / 3600
            weight = math.exp(-hours_ago / 12)  # 12 hour decay
            weighted_sum += activity.risk_score * weight
            total_weight += weight
        
        overall_risk = weighted_sum / total_weight if total_weight > 0 else 0
        
        # Ye kisi user table mein save karo (agar hai to)
        return overall_risk
    
    def get_user_activity_feed(self, user_id, limit=50):
        """Get activity feed for a user"""
        activities = self.UserActivity.query.filter_by(user_id=user_id)\
            .order_by(self.UserActivity.timestamp.desc())\
            .limit(limit).all()
        
        return [a.to_dict() for a in activities]
    
    def get_high_risk_activities(self, threshold=0.5, limit=100):
        """Get all high risk activities"""
        activities = self.UserActivity.query\
            .filter(self.UserActivity.risk_score >= threshold)\
            .order_by(self.UserActivity.timestamp.desc())\
            .limit(limit).all()
        
        return [a.to_dict() for a in activities]