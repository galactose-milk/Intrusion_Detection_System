import re
import groq
import os
from datetime import datetime

# Initialize Groq API Client - use environment variable for security
client = groq.Groq(api_key=os.getenv("GROQ_API_KEY", ""))

# Function to parse log file
def parse_log(file_path):
    logs = []
    with open(file_path, "r") as file:
        log_data = file.readlines()

    log_entry = {}
    for line in log_data:
        if "REQUEST" in line:
            log_entry = {"timestamp": "", "method": "", "url": "", "headers": "", "body": "", "status": "", "response_body": ""}
        elif "Method:" in line:
            log_entry["method"] = line.split(": ")[1].strip()
        elif "URL:" in line:
            log_entry["url"] = line.split(": ")[1].strip()
        elif "Headers:" in line:
            log_entry["headers"] = line.split(": ", 1)[1].strip()
        elif "Body:" in line and "RESPONSE" not in line:
            log_entry["body"] = line.split(": ", 1)[1].strip()
        elif "Status:" in line:
            log_entry["status"] = line.split(": ")[1].strip()
        elif "Body:" in line:
            log_entry["response_body"] = line.split(": ", 1)[1].strip()
        elif "INFO -" in line and "127.0.0.1" in line:
            match = re.search(r"\[(.*?)\]", line)
            if match:
                log_entry["timestamp"] = match.group(1)
                logs.append(log_entry)
                log_entry = {}
    return logs

# Function to analyze logs using Groq API
def analyze_logs_with_llm(logs):
    log_text = "\n".join([f"{log['timestamp']} | {log['method']} {log['url']} | Status: {log['status']}" for log in logs])

    prompt = f"""
    Analyze the following API logs and identify anomalies based on latency, unusual status codes, and patterns.
    If there are slow responses, frequent server restarts, or unusual error patterns, highlight them.

    Logs:
    {log_text}

    Provide an analysis and any critical insights.
    """

    response = client.chat.completions.create(
        model="llama3-70b-8192",  # ✅ Replaced with a supported model
        messages=[{"role": "system", "content": "You are an AI log analysis expert."},
                  {"role": "user", "content": prompt}]
    )

    return response.choices[0].message.content

# Run log analysis
log_file = "/media/galactose/Partition2/Barclays_Hackthon/api_logs.log"  # Change path if needed
logs = parse_log(log_file)
analysis = analyze_logs_with_llm(logs)

print("LLM Analysis Report:")
print(analysis)
