"""
Insider Threat Level Detection System — Behavioral Log-Based Insider Threat Detection
Flask Backend Application
"""
# Database and models
from models import db, UserActivity
from models.risk_engine import RealTimeTracker, RiskEngine, AlertManager
from models.anomaly_detector import AnomalyDetector
from models.data_generator import DataGenerator

from flask import Flask, render_template, jsonify, request, redirect, url_for, session, send_file
import sqlite3, json, random, hashlib, os
from datetime import datetime, timedelta
import io

# Initialize components
risk_engine = RiskEngine()
alert_manager = AlertManager()
anomaly_detector = AnomalyDetector()
real_time_tracker = None  # Will initialize after db

app = Flask(__name__)
app.secret_key = "itds-secret-2024"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///threatguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Initialize real-time tracker
with app.app_context():
    real_time_tracker = RealTimeTracker(db)

# Create tables
with app.app_context():
    db.create_all()
    print("✅ Database tables created/verified")
 
# ─── DB INIT ──────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect("data/threatguard.db")
    conn.row_factory = sqlite3.Row
    return conn
 
def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        department TEXT NOT NULL,
        role TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        baseline_files INTEGER DEFAULT 100,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
 
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        action TEXT NOT NULL,
        resource TEXT,
        ip_address TEXT,
        status TEXT DEFAULT 'normal',
        files_accessed INTEGER DEFAULT 0,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );
 
    CREATE TABLE IF NOT EXISTS risk_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        score REAL NOT NULL,
        level TEXT NOT NULL,
        anomaly_score REAL DEFAULT 0.0,
        computed_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
 
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT NOT NULL,
        details TEXT,
        acknowledged INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
 
    # Seed demo data if empty
    existing = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing == 0:
        dg = DataGenerator()
        dg.seed_demo_data(conn)
 
    conn.close()

# ─── HELPER FUNCTIONS ────────────────────────────────────
def _hash_password(password):
    """Simple password hashing"""
    return hashlib.sha256(password.encode()).hexdigest()
 
# ─── AUTH ROUTES ──────────────────────────────────────────
@app.route("/")
def index():
    return render_template("landing.html")
 
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        uid = request.form.get("user_id", "").strip()
        pwd = request.form.get("password", "").strip()
        h = _hash_password(pwd)
        
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE user_id=? AND password_hash=?", (uid, h)
        ).fetchone()
        conn.close()
        
        if user:
            # Track successful login
            if real_time_tracker:
                try:
                    result = real_time_tracker.track_activity(
                        user_id=user["user_id"],
                        username=user["name"],
                        action="LOGIN_SUCCESS",
                        status="normal",
                        ip_address=request.remote_addr
                    )
                    print(f"✅ Login tracked - Risk: {result['risk_score']}")
                except Exception as e:
                    print(f"⚠️ Tracking error: {e}")
            
            session["user_id"] = user["user_id"]
            session["is_admin"] = bool(user["is_admin"])
            session["name"] = user["name"]
            
            if user["is_admin"]:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("user_dashboard"))
        else:
            # Track failed login
            if real_time_tracker:
                try:
                    real_time_tracker.track_activity(
                        user_id=uid,
                        username=uid,
                        action="LOGIN_FAILED",
                        status="failed",
                        ip_address=request.remote_addr
                    )
                except Exception as e:
                    print(f"⚠️ Tracking error: {e}")
            
            return render_template("login.html", error="Invalid credentials")
    
    return render_template("login.html")
 
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
 
# ─── USER DASHBOARD ───────────────────────────────────────
@app.route("/dashboard")
def user_dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    
    uid = session["user_id"]
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE user_id=?", (uid,)).fetchone()
    risk = conn.execute(
        "SELECT * FROM risk_scores WHERE user_id=? ORDER BY computed_at DESC LIMIT 1", (uid,)
    ).fetchone()
    recent_logs = conn.execute(
        "SELECT * FROM activity_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 20", (uid,)
    ).fetchall()
    my_alerts = conn.execute(
        "SELECT * FROM alerts WHERE user_id=? AND acknowledged=0 ORDER BY created_at DESC LIMIT 5", (uid,)
    ).fetchall()
    conn.close()
    
    return render_template("user_dashboard.html", 
                           user=user, 
                           risk=risk,
                           recent_logs=recent_logs, 
                           my_alerts=my_alerts)
 
# ─── ADMIN DASHBOARD ──────────────────────────────────────
@app.route("/admin")
def admin_dashboard():
    if not session.get("is_admin"):
        return redirect(url_for("login"))
    
    conn = get_db()
    all_users = conn.execute("SELECT * FROM users WHERE is_admin=0").fetchall()
    alerts = conn.execute(
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    high_risk = conn.execute("""
        SELECT u.*, r.score, r.level FROM users u
        JOIN risk_scores r ON u.user_id=r.user_id
        WHERE r.id IN (SELECT MAX(id) FROM risk_scores GROUP BY user_id)
        AND r.level IN ('HIGH','MEDIUM')
        ORDER BY r.score DESC
    """).fetchall()
    conn.close()
    
    return render_template("admin_dashboard.html", 
                           all_users=all_users,
                           alerts=alerts, 
                           high_risk=high_risk)
 
# ─── API ENDPOINTS ────────────────────────────────────────

# 🔴🔴🔴 NEW - Real-time activity feed API 🔴🔴🔴
@app.route('/api/my-activities')
def my_activities():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    if real_time_tracker:
        activities = real_time_tracker.get_user_activity_feed(user_id, limit=20)
        return jsonify(activities)
    return jsonify([])

@app.route("/api/run-detection", methods=["POST"])
def run_detection():
    """Trigger anomaly detection on all users"""
    conn = get_db()
    users = conn.execute("SELECT * FROM users WHERE is_admin=0").fetchall()
    detector = AnomalyDetector()
    risk_engine = RiskEngine()
    alert_manager = AlertManager()
    results = []
 
    for user in users:
        logs = conn.execute(
            "SELECT * FROM activity_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 50",
            (user["user_id"],)
        ).fetchall()
        features = detector.extract_features(logs, user["baseline_files"])
        anomaly_score = detector.predict(features)
        risk_score, level = risk_engine.calculate(anomaly_score, features)
 
        conn.execute(
            "INSERT INTO risk_scores (user_id, score, level, anomaly_score) VALUES (?,?,?,?)",
            (user["user_id"], risk_score, level, anomaly_score)
        )
 
        if level in ("HIGH", "MEDIUM"):
            alert = alert_manager.generate(user["user_id"], features, risk_score, level)
            conn.execute(
                "INSERT INTO alerts (user_id, alert_type, severity, message, details) VALUES (?,?,?,?,?)",
                (alert["user_id"], alert["type"], alert["severity"],
                 alert["message"], json.dumps(alert["details"]))
            )
        results.append({"user_id": user["user_id"], "risk": level, "score": risk_score})
 
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "processed": len(results), "results": results})
 
@app.route("/api/user-activity/<uid>")
def api_user_activity(uid):
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM activity_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 100", (uid,)
    ).fetchall()
    scores = conn.execute(
        "SELECT score, level, computed_at FROM risk_scores WHERE user_id=? ORDER BY computed_at DESC LIMIT 30", (uid,)
    ).fetchall()
    conn.close()
    return jsonify({
        "logs": [dict(r) for r in logs],
        "risk_history": [dict(r) for r in scores]
    })
 
@app.route("/api/user-detail/<uid>")
def api_user_detail(uid):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE user_id=?", (uid,)).fetchone()
    risk = conn.execute(
        "SELECT * FROM risk_scores WHERE user_id=? ORDER BY computed_at DESC LIMIT 1", (uid,)
    ).fetchone()
    logs = conn.execute(
        "SELECT * FROM activity_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 50", (uid,)
    ).fetchall()
    alerts = conn.execute(
        "SELECT * FROM alerts WHERE user_id=? ORDER BY created_at DESC LIMIT 10", (uid,)
    ).fetchall()
    conn.close()
    return jsonify({
        "user": dict(user) if user else {},
        "risk": dict(risk) if risk else {},
        "logs": [dict(r) for r in logs],
        "alerts": [dict(r) for r in alerts]
    })
 
@app.route("/api/alerts")
def api_alerts():
    conn = get_db()
    alerts = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 30").fetchall()
    conn.close()
    return jsonify([dict(a) for a in alerts])
 
@app.route("/api/acknowledge-alert/<int:alert_id>", methods=["POST"])
def ack_alert(alert_id):
    conn = get_db()
    conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "acknowledged"})
 
@app.route("/api/dashboard-stats")
def api_stats():
    conn = get_db()
    total_users = conn.execute("SELECT COUNT(*) FROM users WHERE is_admin=0").fetchone()[0]
    high_risk = conn.execute("""
        SELECT COUNT(*) FROM risk_scores WHERE level='HIGH'
        AND id IN (SELECT MAX(id) FROM risk_scores GROUP BY user_id)
    """).fetchone()[0]
    med_risk = conn.execute("""
        SELECT COUNT(*) FROM risk_scores WHERE level='MEDIUM'
        AND id IN (SELECT MAX(id) FROM risk_scores GROUP BY user_id)
    """).fetchone()[0]
    unacked = conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
    total_events = conn.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
    conn.close()
    return jsonify({
        "total_users": total_users, 
        "high_risk": high_risk,
        "medium_risk": med_risk, 
        "unacked_alerts": unacked,
        "total_events": total_events
    })
 
@app.route("/api/simulate-event/<uid>", methods=["POST"])
def simulate_event(uid):
    """Simulate a suspicious event for demo purposes"""
    event_type = request.json.get("type", "bulk_access")
    conn = get_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
 
    if event_type == "bulk_access":
        files = random.randint(200, 500)
        conn.execute(
            "INSERT INTO activity_logs (user_id,action,resource,ip_address,status,files_accessed,timestamp) VALUES (?,?,?,?,?,?,?)",
            (uid, "BULK_FILE_ACCESS", "/sensitive/payroll/*", "10.0.0.99", "suspicious", files, now)
        )
        
        # Also track in UserActivity
        if real_time_tracker:
            real_time_tracker.track_activity(
                user_id=uid,
                username=uid,
                action="BULK_FILE_ACCESS",
                resource="/sensitive/payroll/*",
                ip_address="10.0.0.99",
                status="suspicious",
                files_accessed=files
            )
            
    elif event_type == "off_hours":
        conn.execute(
            "INSERT INTO activity_logs (user_id,action,resource,ip_address,status,files_accessed,timestamp) VALUES (?,?,?,?,?,?,?)",
            (uid, "LOGIN", "system", "unknown_ip", "suspicious", 0, now)
        )
        
        if real_time_tracker:
            real_time_tracker.track_activity(
                user_id=uid,
                username=uid,
                action="OFF_HOURS_LOGIN",
                resource="system",
                ip_address="unknown_ip",
                status="suspicious",
                files_accessed=0
            )
            
    elif event_type == "failed_login":
        for i in range(12):
            conn.execute(
                "INSERT INTO activity_logs (user_id,action,resource,ip_address,status,files_accessed,timestamp) VALUES (?,?,?,?,?,?,?)",
                (uid, "LOGIN_FAILED", "system", "185.x.x.x", "failed", 0, now)
            )
            
            if real_time_tracker and i == 0:  # Track only once to avoid spam
                real_time_tracker.track_activity(
                    user_id=uid,
                    username=uid,
                    action="LOGIN_FAILED",
                    resource="system",
                    ip_address="185.x.x.x",
                    status="failed",
                    files_accessed=0
                )
    
    conn.commit()
    conn.close()
    return jsonify({"status": "simulated", "type": event_type})

# ─── LANDING PAGE ─────────────────────────────────────────
@app.route("/landing")
def landing():
    return render_template("landing.html")
 
# ─── AUDIT LOGS PAGE ──────────────────────────────────────
@app.route("/audit-logs")
def audit_logs():
    if not session.get("is_admin"):
        return redirect(url_for("login"))
    return render_template("audit_logs.html")
 
@app.route("/api/all-logs")
def api_all_logs():
    if not session.get("is_admin"):
        return jsonify([]), 403
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 500"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in logs])
 
# ─── PDF REPORT ───────────────────────────────────────────
@app.route("/api/report/<uid>")
def api_report(uid):
    if not session.get("is_admin"):
        return redirect(url_for("login"))
    try:
        from models.pdf_reporter import generate_report
        conn = get_db()
        user   = conn.execute("SELECT * FROM users WHERE user_id=?", (uid,)).fetchone()
        risk   = conn.execute(
            "SELECT * FROM risk_scores WHERE user_id=? ORDER BY computed_at DESC LIMIT 1", (uid,)
        ).fetchone()
        logs   = conn.execute(
            "SELECT * FROM activity_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 50", (uid,)
        ).fetchall()
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE user_id=? ORDER BY created_at DESC LIMIT 10", (uid,)
        ).fetchall()
        conn.close()
        
        pdf_bytes = generate_report(
            user=dict(user) if user else {},
            risk=dict(risk) if risk else {},
            logs=[dict(r) for r in logs],
            alerts=[dict(r) for r in alerts],
        )
        buf = io.BytesIO(pdf_bytes)
        buf.seek(0)
        return send_file(
            buf, 
            mimetype="application/pdf", 
            as_attachment=True,
            download_name=f"threatguard_{uid}_{datetime.now().strftime('%Y%m%d')}.pdf"
        )
    except ImportError:
        return jsonify({"error": "Run: pip install reportlab"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)