import re
import csv
import json
import argparse
import requests
from collections import defaultdict

def get_ip_location(ip):                                                    # get ip location for each suspicious IP
    """Fetch geolocation of an IP using ipinfo.io"""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3) # fetch the IP location from ipinfo.io
        if response.status_code == 200:
            data = response.json()                                          # parse JSON data
            city = data.get("city")
            country = data.get("country")
            if city and country:
                return f"{city}, {country}"                                 # return city, country if available
            elif country:
                return country                                               # return country if city not available
            else:
                return "Unknown"                                            # return unknown if no location info
    except requests.RequestException:                                        # handle request exceptions
        return "Unknown"                                                    # return unknown if exception occurs
    return "Unknown"

def analyze_logs(file_path, threshold, output_format=None):                 
    failed_attempts = defaultdict(int)                                       # dictionary to count failed attempts per IP

    # Read and count failed attempts from log file
    with open(file_path, "r") as f:
        for line in f:
            if "LOGIN FAILED" in line:
                match = re.search(r"IP: (\d+\.\d+\.\d+\.\d+)", line)        # regex to find IP address
                if match:
                    ip = match.group(1)                                     # extract IP address
                    failed_attempts[ip] += 1                                # increment count for that IP

    # Filter IPs that exceed the threshold
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count >= threshold}

    # Fetch location for each suspicious IP once
    ip_locations = {ip: get_ip_location(ip) for ip in suspicious_ips.keys()}  # dictionary of IP -> location

    # Print results to console
    print(f"Suspicious IPs with >= {threshold} failed logins:\n")            # print header
    for ip, count in suspicious_ips.items():                                 # iterate through suspicious IPs
        print(f"⚠️  {ip} had {count} failed attempts (Location: {ip_locations[ip]})") # show IP, count, location

    # Export results to CSV or JSON if requested
    if output_format == "csv":
        with open("suspicious_ips.csv", "w", newline='') as csvfile:         # create/open CSV file
            fieldnames = ['IP Address', 'Failed Attempts', 'Location']       # define field names
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)          # create CSV writer
            writer.writeheader()    
            for ip, count in suspicious_ips.items():                          # iterate through suspicious IPs
                writer.writerow({'IP Address': ip, 'Failed Attempts': count, 'Location': ip_locations[ip]}) # write row
        print("\n✅ Results exported to suspicious_ips.csv")                   # confirmation message
        
    elif output_format == "json":
        output_data = [
            {'IP Address': ip, 'Failed Attempts': count, 'Location': ip_locations[ip]} # prepare JSON data
            for ip, count in suspicious_ips.items()
        ]
        with open("suspicious_ips.json", "w") as jsonfile:                    # write JSON file
            json.dump(output_data, jsonfile, indent=4)
        print("\n✅ Results exported to suspicious_ips.json")                  # confirmation message

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze log files for suspicious IPs with failed login attempts.") # script description
    parser.add_argument("logfile", help="Path to the log file to analyze")         # required logfile argument
    parser.add_argument("--threshold", type=int, default=5, help="Threshold for failed login attempts to consider an IP suspicious") # threshold option
    parser.add_argument("--output", choices=["csv", "json"], help="Export results to specified format") # export option

    args = parser.parse_args()
    analyze_logs(args.logfile, args.threshold, args.output)                        # run analyzer with arguments
