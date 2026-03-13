"""
Demo Data Generator
Seeds the database with realistic synthetic users, logs, risk scores, and alerts
"""

import hashlib, random
from datetime import datetime, timedelta

DEPARTMENTS = ["Finance", "IT", "HR", "Sales", "Engineering", "Operations", "Legal"]
ACTIONS = ["LOGIN", "FILE_READ", "FILE_DOWNLOAD", "FILE_WRITE", "EMAIL_SENT",
           "USB_WRITE", "SYSTEM_ACCESS", "DB_QUERY", "PRINT", "VPN_CONNECT"]
FILES = ["/reports/q1.xlsx", "/hr/payroll.csv", "/shared/policies.pdf",
         "/projects/blueprint.docx", "/finance/accounts.xlsx",
         "/sensitive/credentials.txt", "/backup/db_dump.sql", "/admin/config.yaml"]
IPS = ["10.0.1.42", "10.0.1.43", "10.0.1.88", "192.168.1.5", "unknown_ip_CN",
       "vpn_ip_45.33.x", "10.0.0.99", "185.220.x.x"]


def _hash(pw): return hashlib.sha256(pw.encode()).hexdigest()
def _rand_time(base, hours_back=48):
    delta = timedelta(hours=random.uniform(0, hours_back),
                      minutes=random.randint(0, 59))
    return (base - delta).strftime("%Y-%m-%d %H:%M:%S")


class DataGenerator:
    # 🔴🔴🔴 CHANGE 1: CONSTRUCTOR ADD KARO 🔴🔴🔴
    def __init__(self, tracker=None):
        """Initialize DataGenerator with optional RealTimeTracker"""
        self.tracker = tracker
        print("✅ DataGenerator initialized with tracker" if tracker else "⚠️ DataGenerator initialized without tracker")
    
    def seed_demo_data(self, conn):
        c = conn.cursor()
        now = datetime.now()

        # ── Admin ──────────────────────────────────────────
        c.execute("""INSERT OR IGNORE INTO users
            (user_id,name,department,role,password_hash,is_admin,baseline_files)
            VALUES (?,?,?,?,?,?,?)""",
            ("admin_01", "Admin Kumar", "Security", "CISO",
             _hash("admin123"), 1, 0))

        # ── Employees ─────────────────────────────────────
        employees = [
            ("EMP_001", "Rahul Kumar",     "IT",          "Analyst",       "pass123", 100),
            ("EMP_002", "Priya Sharma",    "Finance",     "Senior Analyst","pass123", 80),
            ("EMP_003", "Anil Mehta",      "Finance",     "Analyst",       "pass123", 90),
            ("EMP_004", "Deepika Rao",     "HR",          "Manager",       "pass123", 60),
            ("EMP_005", "Sanjeev Patel",   "Sales",       "Executive",     "pass123", 70),
            ("EMP_006", "Neha Gupta",      "Engineering", "Developer",     "pass123", 120),
            ("EMP_007", "Vijay Nair",      "IT",          "SysAdmin",      "pass123", 150),
            ("EMP_008", "Rekha Joshi",     "Operations",  "Coordinator",   "pass123", 50),
        ]
        for uid, name, dept, role, pw, baseline in employees:
            c.execute("""INSERT OR IGNORE INTO users
                (user_id,name,department,role,password_hash,baseline_files)
                VALUES (?,?,?,?,?,?)""",
                (uid, name, dept, role, _hash(pw), baseline))

        # ── Activity logs ─────────────────────────────────
        def add_logs(uid, profile):
            for _ in range(profile["events"]):
                action = random.choice(ACTIONS)
                files_n = random.randint(*profile["files_range"])
                hour = random.choice(profile["hours"])
                ts = (now - timedelta(
                    hours=random.randint(0, 168),
                    minutes=random.randint(0, 59))
                ).replace(hour=hour)
                
                status = "suspicious" if files_n > 150 or hour < 6 else "normal"
                ip = random.choice(profile["ips"])
                
                # Format timestamp for SQL
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
                
                # 🔴🔴🔴 EXISTING CODE - activity_logs table mein insert 🔴🔴🔴
                c.execute("""INSERT INTO activity_logs
                    (user_id,action,resource,ip_address,status,files_accessed,timestamp)
                    VALUES (?,?,?,?,?,?,?)""",
                    (uid, action, random.choice(FILES), ip, status, files_n, ts_str))
                
                # 🔴🔴🔴 CHANGE 2: UserActivity table mein bhi insert karo 🔴🔴🔴
                # Ye tab kaam karega jab RealTimeTracker initialize ho
                if hasattr(self, 'tracker') and self.tracker:
                    try:
                        self.tracker.track_activity(
                            user_id=uid,
                            username=uid,  # username same as user_id for demo
                            action=action,
                            resource=random.choice(FILES),
                            ip_address=ip,
                            status=status,
                            files_accessed=files_n
                        )
                    except Exception as e:
                        print(f"⚠️ Error tracking activity in data_generator for user {uid}: {e}")
                # 🔴🔴🔴 CHANGE 2 END 🔴🔴🔴

        # Normal users
        normal_profile = {"events": 40, "files_range": (5, 80),
                          "hours": list(range(9, 19)), "ips": IPS[:3]}
        for uid, *_ in employees[:-3]:
            add_logs(uid, normal_profile)

        # Suspicious users
        add_logs("EMP_006", {"events": 60, "files_range": (20, 500),
                              "hours": [1, 2, 3, 22, 23] + list(range(9, 18)),
                              "ips": IPS})
        add_logs("EMP_007", {"events": 50, "files_range": (100, 600),
                              "hours": [2, 3, 4] + list(range(9, 18)),
                              "ips": IPS[3:]})
        add_logs("EMP_008", {"events": 30, "files_range": (0, 30),
                              "hours": list(range(9, 18)), "ips": IPS[:2]})

        # Failed logins for EMP_005
        for _ in range(12):
            ts_str = _rand_time(now, 24)
            c.execute("""INSERT INTO activity_logs
                (user_id,action,resource,ip_address,status,files_accessed,timestamp)
                VALUES (?,?,?,?,?,?,?)""",
                ("EMP_005", "LOGIN_FAILED", "system", "185.220.x.x",
                 "failed", 0, ts_str))
            
            # 🔴🔴🔴 Failed login ko bhi UserActivity mein track karo 🔴🔴🔴
            if hasattr(self, 'tracker') and self.tracker:
                try:
                    self.tracker.track_activity(
                        user_id="EMP_005",
                        username="EMP_005",
                        action="LOGIN_FAILED",
                        resource="system",
                        ip_address="185.220.x.x",
                        status="failed",
                        files_accessed=0
                    )
                except Exception as e:
                    print(f"⚠️ Error tracking failed login: {e}")

        # ── Risk scores ───────────────────────────────────
        risk_data = [
            ("EMP_001", 12.0, "LOW",    0.12),
            ("EMP_002", 18.0, "LOW",    0.18),
            ("EMP_003", 24.0, "LOW",    0.24),
            ("EMP_004", 31.0, "LOW",    0.31),
            ("EMP_005", 53.0, "MEDIUM", 0.53),
            ("EMP_006", 87.0, "HIGH",   0.87),
            ("EMP_007", 81.0, "HIGH",   0.81),
            ("EMP_008",  8.0, "LOW",    0.08),
        ]
        for uid, score, level, ascore in risk_data:
            c.execute("""INSERT INTO risk_scores
                (user_id,score,level,anomaly_score) VALUES (?,?,?,?)""",
                (uid, score, level, ascore))

        # ── Alerts ────────────────────────────────────────
        alerts = [
            ("EMP_006", "BULK_FILE_ACCESS", "HIGH",
             "ALERT: Bulk File Access | User: EMP_006 | Files: 487 (Baseline: 120) | Risk: HIGH",
             '{"files_accessed":487,"baseline":120,"ratio":4.06,"failed_logins":0,"off_hours":4,"risk_score":87.0}'),
            ("EMP_007", "DATA_EXFIL", "HIGH",
             "ALERT: Potential Data Exfiltration | User: EMP_007 | Files: 612 (Baseline: 150) | Risk: HIGH",
             '{"files_accessed":612,"baseline":150,"ratio":4.08,"failed_logins":0,"off_hours":6,"risk_score":81.0}'),
            ("EMP_005", "FAILED_LOGIN", "MEDIUM",
             "ALERT: Repeated Login Failures | User: EMP_005 | 12 Failed Attempts | Risk: MEDIUM",
             '{"files_accessed":0,"baseline":70,"failed_logins":12,"risk_score":53.0}'),
        ]
        for uid, atype, sev, msg, det in alerts:
            c.execute("""INSERT INTO alerts
                (user_id,alert_type,severity,message,details) VALUES (?,?,?,?,?)""",
                (uid, atype, sev, msg, det))

        conn.commit()
        print("✅ Demo data seeded successfully!")