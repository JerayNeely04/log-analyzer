# log_analyzer.py
import re
import requests

def get_ip_location(ip):
    """Fetch location info for an IP."""
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
    except requests.RequestException:
        pass
    return "Unknown"

def analyze_log(filepath, threshold=3):
    """
    Analyze log file for suspicious IPs.
    Returns a dict of IP -> count exceeding threshold.
    """
    suspicious_ips = {}
    with open(filepath, "r") as f:
        for line in f:
            if "LOGIN FAILED" in line:
                match = re.search(r"IP:\s*([\d\.]+)", line)
                if match:
                    ip = match.group(1)
                    suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

    # Keep only IPs exceeding threshold
    return {ip: count for ip, count in suspicious_ips.items() if count >= threshold}
