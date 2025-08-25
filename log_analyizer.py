import re
from collections import defaultdict   #starts every new dictionary entry with 0

def analyze_log(file_path):
        failed_attempts = defaultdict(int)   #defaultdict to count failed attempts per IP
        
        with open(file_path, 'r') as file:
            for line in file:                   #reads every line in the log file
                if "LOGIN FAILED" in line:      #checks for failed login attempts
                    match = re.search(r"IP: (\d+\.\d+\.\d+\.\d+)", line)         #var matches the IP address pattern
                    if match:
                        ip= match.group(1)                                  #if matched, extract the IP address
                        failed_attempts[ip] += 1                            #increment the count for that IP address

        print("Suspicios IPs with multiple failed login attempts:")
        for ip, count in failed_attempts.items():                           #iterates through the dictionary
            if count >= 3:                                                   #checks if failed attempts are 3 or more         
                print(f"IP: {ip}, Failed Attempts: {count}")
    
if __name__ == "__main__":
    log_file_path = 'server.log'                                            # Replace with your log file path
    analyze_log("Sample_logs.txt")
                
    