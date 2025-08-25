import re
from collections import defaultdict

def analyze_log(file_path):
        failed_attempts = defaultdict(int)
        
        with open(file_path, 'r') as file:
            for line in file:
                if "LOGIN FAILED" in line:
                    match = re.search(r"IP: (\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        ip= match.group(1)
                        failed_attempts[ip] += 1

        print("Suspicios IPs with multiple failed login attempts:")
        for ip, count in failed_attempts.items():
            if count >= 3:
                print(f"IP: {ip}, Failed Attempts: {count}")
    
if __name__ == "__main__":
    log_file_path = 'server.log'  # Replace with your log file path
    analyze_log("Sample_logs.txt")
                
    