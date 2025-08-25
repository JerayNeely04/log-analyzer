Log Analyzer Dashboard

A Python tool with a Flask web dashboard that parses log files to detect suspicious login attempts. Designed for security analysts and SOC enthusiasts to quickly identify potential brute-force attacks.

Features

Reads log files in plain text format (e.g., sample_logs.txt)

Detects multiple failed login attempts from the same IP

Flags suspicious IP addresses for further investigation

Fetches geolocation data for IPs using ipinfo.io

Displays results in an easy-to-read Flask dashboard

Can export results to CSV or JSON (future expansion)