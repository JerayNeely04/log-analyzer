import re
import csv
import json
import argparse
import requests
from collections import defaultdict

def get_ip_location(ip):                                                    #get ip location 
    """Fetch geolocation of an IP using ipinfo.io"""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")             #fetch the ip location from ipinfo.io
        if response.status_code == 200:
            data = response.json()                                          #parse json data
            return data.get("country", "Unknown")
    except Exception:                                                       #in case of any exception
        return "Unknown"                                                    #return unknown if exception occurs
    return "Unknown"

def analyze_logs(file_path, threshold, output_format):
    failed_attempts = defaultdict(int)

    # Read and count failed attempts
    with open(file_path, "r") as f:
        for line in f:
            if "LOGIN FAILED" in line:
                match = re.search(r"IP: (\d+\.\d+\.\d+\.\d+)", line)       #regex to find ip address
                if match:
                    ip = match.group(1)                                     #extract ip address
                    failed_attempts[ip] += 1                                #increment count for that ip

    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count >= threshold}

    # Print to console
    print(f"Suspicious IPs with >= {threshold} failed logins:\n")           #print header
    for ip, count in suspicious_ips.items():                                #iterate through suspicious ips
        location = get_ip_location(ip)                                      #get location of the ip                  
        print(f"⚠️  {ip} had {count} failed attempts (Location: {location})")
        
    # Export results to csv or json
    if output_format == "csv":
        with open("suspicious_ips.csv", "w", newline='') as csvfile:            #create/open csv file
            fieldnames = ['IP Address', 'Failed Attempts', 'Location']         #define field names
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)             #create csv writer
            writer.writeheader()    
            for ip, count in suspicious_ips.items():                           #iterate through suspicious ips 
                location = get_ip_location(ip)                                   #get location of the ip
                writer.writerow({'IP Address': ip, 'Failed Attempts': count, 'Location': location})
        print("\nResults exported to suspicious_ips.csv")
        
    elif output_format == "json":
        output_data = [
            {'IP Address': ip, 'Failed Attempts': count, 'Location': get_ip_location(ip)}
            for ip, count in suspicious_ips.items()
        ]
        with open("suspicious_ips.json", "w") as jsonfile:
            json.dump(output_data, jsonfile, indent=4)
        print("\nResults exported to suspicious_ips.json")
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze log files for suspicious IPs with failed login attempts.")
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--threshold", type=int, default=5, help="Threshold for failed login attempts to consider an IP suspicious")
    parser.add_argument("--output", choices=["csv", "json"], help="Export results to specified format")
    
    args = parser.parse_args()
    
    analyze_logs(args.logfile, args.threshold, args.output)
    
        