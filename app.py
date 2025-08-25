# app.py
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
import os
from datetime import datetime
from log_analyzer import analyze_log, get_ip_location

app = Flask(__name__)

# ------------------- Config -------------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/log_analyzer?unix_socket=/tmp/mysql.sock'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Ensure uploads folder exists
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ------------------- Database Models -------------------
class UploadedFile(db.Model):
    __tablename__ = 'uploaded_files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    upload_time = db.Column(db.DateTime, default=db.func.current_timestamp())
    ips = db.relationship('SuspiciousIP', backref='file', lazy='joined')


class SuspiciousIP(db.Model):
    __tablename__ = 'suspicious_ips'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), nullable=False)
    count = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(100))
    file_id = db.Column(db.Integer, db.ForeignKey('uploaded_files.id'), nullable=False)

# ------------------- Routes -------------------
@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    if request.method == "POST":
        uploaded_file = request.files.get("logfile")
        threshold = int(request.form.get("threshold", 3))

        if uploaded_file and uploaded_file.filename != "":
            # Use timestamp to avoid overwriting files
            filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uploaded_file.filename}"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            uploaded_file.save(filepath)

            # Analyze log
            ip_counts = analyze_log(filepath, threshold)
            results = []

            # Save file to DB
            file_record = UploadedFile(filename=filename)
            db.session.add(file_record)
            db.session.commit()  # commit to get ID

            for ip, count in ip_counts.items():
                location = get_ip_location(ip)
                ip_record = SuspiciousIP(
                    ip=ip,
                    count=count,
                    location=location,
                    file_id=file_record.id
                )
                db.session.add(ip_record)
                results.append({"ip": ip, "count": count, "location": location})

            db.session.commit()

    return render_template("index.html", results=results)


@app.route("/history")
def history():
    files = UploadedFile.query.options(joinedload(UploadedFile.ips))\
        .order_by(UploadedFile.upload_time.desc()).all()
    return render_template("history.html", files=files)


@app.route("/file/<int:file_id>")
def file_detail(file_id):
    file = UploadedFile.query.options(joinedload(UploadedFile.ips)).get_or_404(file_id)
    return render_template("file_detail.html", file=file)


# ------------------- Run App -------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5050)
