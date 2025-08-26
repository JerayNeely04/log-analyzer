# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
import os
from datetime import datetime
from log_analyzer import analyze_log, get_ip_location  # Custom module to analyze logs and fetch IP locations

# ------------------- App Initialization -------------------
app = Flask(__name__)
app.secret_key = "supersecretkey"  # Required for flash messages to show success/error notifications

# ------------------- Config -------------------
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'mysql+pymysql://root@localhost/log_analyzer?unix_socket=/tmp/mysql.sock'  # Database connection string
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable unnecessary tracking to save resources
app.config['UPLOAD_FOLDER'] = "uploads"  # Directory to store uploaded log files
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # Limit uploads to 50 MB

# Initialize SQLAlchemy ORM
db = SQLAlchemy(app)

# Ensure the uploads folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ------------------- Database Models -------------------
class UploadedFile(db.Model):
    """Represents a log file uploaded by the user."""
    __tablename__ = 'uploaded_files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    upload_time = db.Column(db.DateTime, default=db.func.current_timestamp())  # Auto-set upload timestamp
    ips = db.relationship('SuspiciousIP', backref='file', lazy='joined')  # One-to-many relationship with IPs


class SuspiciousIP(db.Model):
    """Stores suspicious IP addresses found in uploaded log files."""
    __tablename__ = 'suspicious_ips'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), nullable=False)
    count = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(100))  # City, Country or Unknown
    file_id = db.Column(db.Integer, db.ForeignKey('uploaded_files.id'), nullable=False)  # Link to UploadedFile


# ------------------- Routes -------------------
@app.route("/", methods=["GET", "POST"])
def index():
    """Main page: handles log file upload, analysis, and displays results."""
    results = []

    if request.method == "POST":
        uploaded_file = request.files.get("logfile")
        threshold = int(request.form.get("threshold", 3))  # Minimum number of failed logins to flag IP

        # Validate file upload
        if not uploaded_file or uploaded_file.filename == "":
            flash("No file selected!", "error")
            return redirect(request.url)

        # Save uploaded file with timestamp to prevent overwriting
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{timestamp}_{uploaded_file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(filepath)

        # Analyze the log file and count suspicious IPs
        ip_counts = analyze_log(filepath, threshold)
        results = []

        # Store uploaded file record in database
        file_record = UploadedFile(filename=filename)
        db.session.add(file_record)
        db.session.commit()  # Commit to generate file ID for foreign key

        # Save each suspicious IP record to database
        for ip, count in ip_counts.items():
            location = get_ip_location(ip)  # Lookup IP location
            ip_record = SuspiciousIP(
                ip=ip,
                count=count,
                location=location,
                file_id=file_record.id
            )
            db.session.add(ip_record)
            results.append({"ip": ip, "count": count, "location": location})

        db.session.commit()
        flash(f"File uploaded and analyzed successfully: {filename}", "success")

    # Render main page with results table
    return render_template("index.html", results=results)


@app.route("/history")
def history():
    """Displays a list of all uploaded files with their suspicious IPs."""
    files = UploadedFile.query.options(joinedload(UploadedFile.ips))\
        .order_by(UploadedFile.upload_time.desc()).all()
    return render_template("history.html", files=files)


@app.route("/file/<int:file_id>")
def file_detail(file_id):
    """Displays detailed information about a single uploaded file and its suspicious IPs."""
    file = UploadedFile.query.options(joinedload(UploadedFile.ips)).get_or_404(file_id)
    return render_template("file_detail.html", file=file)


# ------------------- Run App -------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create tables in the database if they do not exist
    app.run(debug=True, port=5050)  # Run Flask app on port 5050 in debug mode
