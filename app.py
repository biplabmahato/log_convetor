import json
import os
import csv
from tkinter import Tk
from tkinter.filedialog import askopenfilename


def parse_aws_log(log):
    return {
        "timestamp": log.get("eventTime"),
        "cloud_provider": "AWS",
        "service": log.get("eventSource"),
        "action": log.get("eventName"),
        "user": log.get("userIdentity", {}).get("userName") if isinstance(log.get("userIdentity"), dict) else log.get("userIdentity"),
        "resource": log.get("requestParameters", {}).get("bucketName") if isinstance(log.get("requestParameters"), dict) else log.get("resource"),
        "status": log.get("responseElements", {}).get("x-amz-request-id", "SUCCESS") if isinstance(log.get("responseElements"), dict) else log.get("status", "SUCCESS")
    }


def parse_gcp_log(log):
    return {
        "timestamp": log.get("timestamp"),
        "cloud_provider": "GCP",
        "service": log.get("resource", {}).get("type") if isinstance(log.get("resource"), dict) else log.get("resource"),
        "action": log.get("protoPayload", {}).get("methodName") if isinstance(log.get("protoPayload"), dict) else log.get("action"),
        "user": log.get("protoPayload", {}).get("authenticationInfo", {}).get("principalEmail") if isinstance(log.get("protoPayload"), dict) else log.get("user"),
        "resource": log.get("resource", {}).get("labels", {}).get("project_id") if isinstance(log.get("resource"), dict) else log.get("resource"),
        "status": log.get("severity", "INFO")
    }


def parse_azure_log(log):
    return {
        "timestamp": log.get("timeGenerated"),
        "cloud_provider": "Azure",
        "service": log.get("category"),
        "action": log.get("operationName"),
        "user": log.get("caller"),
        "resource": log.get("resourceId"),
        "status": log.get("status", {}).get("value", "Success") if isinstance(log.get("status"), dict) else log.get("status", "Success")
    }


def normalize_log(log):
    try:
        if "eventTime" in log and "eventSource" in log:
            return parse_aws_log(log)
        elif "protoPayload" in log:
            return parse_gcp_log(log)
        elif "resourceId" in log and "caller" in log:
            return parse_azure_log(log)
        else:
            return None
    except Exception as e:
        return None


def load_json_logs(filepath):
    """Load logs from JSON file"""
    with open(filepath, 'r') as f:
        data = json.load(f)

    # If top-level is a list, return it
    if isinstance(data, list):
        return data
    # If top-level contains a 'Records' key or similar
    elif isinstance(data, dict):
        for key in ["Records", "entries", "logEvents"]:
            if key in data:
                return data[key]
        return [data]  # maybe single log
    return []


def load_csv_logs(filepath):
    """Load logs from CSV file and convert to list of dictionaries"""
    logs = []
    with open(filepath, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            logs.append(row)
    return logs


def write_csv(logs, output_file="normalized_logs.csv"):
    if not logs:
        print("No valid logs to write.")
        return

    keys = logs[0].keys()
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(logs)
    print(f" Logs written to {output_file}")


def main():
    print("Select a log file (JSON or CSV format for AWS / GCP / Azure)...")
    Tk().withdraw()
    filepath = askopenfilename(filetypes=[
        ("All supported files", "*.json;*.csv"),
        ("JSON files", "*.json"),
        ("CSV files", "*.csv")
    ])

    if not filepath:
        print("No file selected.")
        return

    print(f"🔍 Processing: {os.path.basename(filepath)}")

    # Determine file type and load accordingly
    file_extension = os.path.splitext(filepath)[1].lower()
    
    if file_extension == '.json':
        raw_logs = load_json_logs(filepath)
    elif file_extension == '.csv':
        raw_logs = load_csv_logs(filepath)
    else:
        print("❌ Unsupported file format. Please select a JSON or CSV file.")
        return

    print(f"📊 Found {len(raw_logs)} log entries.")

    normalized = []
    skipped = 0

    for log in raw_logs:
        norm = normalize_log(log)
        if norm:
            normalized.append(norm)
        else:
            skipped += 1

    print(f"✅ Normalized {len(normalized)} logs.")
    if skipped > 0:
        print(f"⚠️ Skipped {skipped} unrecognized entries.")

    write_csv(normalized)


if __name__ == "__main__":
    main()
