from flask import Flask, render_template, request
from log_analyizer import analyze_logs, get_ip_location
import os

app = Flask(__name__)
@app.route("/", methods=["GET", "POST"])

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    if request.method == "POST":
        threshold = int(request.form.get("threshold", 3))
        logfile = request.form.get("logfile", "Sample_logs.txt")  # <-- use form instead of files

        # Make sure file exists
        if os.path.exists(logfile):
            failed_attempts = analyze_logs(logfile, threshold)
            for ip, count in failed_attempts.items():
                location = get_ip_location(ip)
                results.append({"ip": ip, "count": count, "location": location})
        else:
            results.append({"error": f"File {logfile} not found."})

    return render_template("index.html", results=results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)
