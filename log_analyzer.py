from flask import Flask, render_template, request
import os
import requests
import re

app = Flask(__name__)

if not os.path.exists("uploads"):
    os.makedirs("uploads")


def get_ip_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        if response.status_code == 200:
            data = response.json()
            city = data.get("city")
            country = data.get("country")
            if city and country:
                return f"{city}, {country}"
            elif country:
                return country
        return "Unknown"
    except requests.RequestException:
        return "Unknown"


def analyze_log(filepath, threshold=3):
    suspicious_ips = {}
    with open(filepath, "r") as f:
        for line in f:
            if "LOGIN FAILED" in line:  # match failed login lines
                match = re.search(r"IP:\s*([\d\.]+)", line)
                if match:
                    ip = match.group(1)
                    suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

    # Filter by threshold
    suspicious_ips = {ip: count for ip, count in suspicious_ips.items() if count >= threshold}

    # Build results list
    results = [{"ip": ip, "count": count, "location": get_ip_location(ip)} for ip, count in suspicious_ips.items()]

    return results


@app.route("/", methods=["GET", "POST"])        
def index():
    results = []
    if request.method == "POST":
        uploaded_file = request.files.get("logfile")           
        threshold = int(request.form.get("threshold", 3))

        if uploaded_file and uploaded_file.filename != "":
            filepath = os.path.join("uploads", uploaded_file.filename)
            uploaded_file.save(filepath)
            results = analyze_log(filepath, threshold)

    return render_template("index.html", results=results)


if __name__ == "__main__":
    app.run(debug=True, port=5050)
