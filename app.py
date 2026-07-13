import streamlit as st
import json
import csv
import os
import pandas as pd
from io import StringIO

st.set_page_config(
    page_title="Cloud Log Normalizer",
    page_icon="☁️",
    layout="wide"
)

# ------------------------------
# Log Parsers
# ------------------------------

def parse_aws_log(log):
    return {
        "timestamp": log.get("eventTime"),
        "cloud_provider": "AWS",
        "service": log.get("eventSource"),
        "action": log.get("eventName"),
        "user": (
            log.get("userIdentity", {}).get("userName")
            if isinstance(log.get("userIdentity"), dict)
            else log.get("userIdentity")
        ),
        "resource": (
            log.get("requestParameters", {}).get("bucketName")
            if isinstance(log.get("requestParameters"), dict)
            else log.get("resource")
        ),
        "status": (
            log.get("responseElements", {}).get("x-amz-request-id", "SUCCESS")
            if isinstance(log.get("responseElements"), dict)
            else log.get("status", "SUCCESS")
        ),
    }


def parse_gcp_log(log):
    return {
        "timestamp": log.get("timestamp"),
        "cloud_provider": "GCP",
        "service": (
            log.get("resource", {}).get("type")
            if isinstance(log.get("resource"), dict)
            else log.get("resource")
        ),
        "action": (
            log.get("protoPayload", {}).get("methodName")
            if isinstance(log.get("protoPayload"), dict)
            else log.get("action")
        ),
        "user": (
            log.get("protoPayload", {})
            .get("authenticationInfo", {})
            .get("principalEmail")
            if isinstance(log.get("protoPayload"), dict)
            else log.get("user")
        ),
        "resource": (
            log.get("resource", {})
            .get("labels", {})
            .get("project_id")
            if isinstance(log.get("resource"), dict)
            else log.get("resource")
        ),
        "status": log.get("severity", "INFO"),
    }


def parse_azure_log(log):
    return {
        "timestamp": log.get("timeGenerated"),
        "cloud_provider": "Azure",
        "service": log.get("category"),
        "action": log.get("operationName"),
        "user": log.get("caller"),
        "resource": log.get("resourceId"),
        "status": (
            log.get("status", {}).get("value", "Success")
            if isinstance(log.get("status"), dict)
            else log.get("status", "Success")
        ),
    }


# ------------------------------
# Normalize
# ------------------------------

def normalize_log(log):
    try:
        if "eventTime" in log and "eventSource" in log:
            return parse_aws_log(log)

        elif "protoPayload" in log:
            return parse_gcp_log(log)

        elif "resourceId" in log and "caller" in log:
            return parse_azure_log(log)

        return None

    except Exception:
        return None


# ------------------------------
# Loaders
# ------------------------------

def load_json_logs(uploaded_file):
    data = json.load(uploaded_file)

    if isinstance(data, list):
        return data

    elif isinstance(data, dict):
        for key in ["Records", "entries", "logEvents"]:
            if key in data:
                return data[key]

        return [data]

    return []


def load_csv_logs(uploaded_file):
    string_data = StringIO(uploaded_file.getvalue().decode("utf-8"))
    reader = csv.DictReader(string_data)
    return list(reader)


# ------------------------------
# UI
# ------------------------------

st.title("☁️ Cloud Log Normalizer")
st.write(
    """
Upload AWS CloudTrail, Google Cloud Logging, or Azure Activity Logs
(JSON or CSV). The application will normalize them into a common format.
"""
)

uploaded_file = st.file_uploader(
    "Choose a log file",
    type=["json", "csv"]
)

if uploaded_file:

    extension = os.path.splitext(uploaded_file.name)[1].lower()

    if extension == ".json":
        raw_logs = load_json_logs(uploaded_file)

    elif extension == ".csv":
        raw_logs = load_csv_logs(uploaded_file)

    else:
        st.error("Unsupported file format.")
        st.stop()

    st.success(f"Loaded {len(raw_logs)} log entries.")

    normalized_logs = []
    skipped = 0

    for log in raw_logs:
        normalized = normalize_log(log)

        if normalized:
            normalized_logs.append(normalized)
        else:
            skipped += 1

    st.metric("Normalized Logs", len(normalized_logs))
    st.metric("Skipped Logs", skipped)

    if len(normalized_logs) > 0:

        df = pd.DataFrame(normalized_logs)

        st.subheader("Normalized Logs")

        st.dataframe(df, use_container_width=True)

        st.subheader("Statistics")

        col1, col2 = st.columns(2)

        with col1:
            st.write("### Cloud Provider Distribution")
            st.bar_chart(df["cloud_provider"].value_counts())

        with col2:
            st.write("### Status Distribution")
            st.bar_chart(df["status"].value_counts())

        csv_data = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="📥 Download Normalized CSV",
            data=csv_data,
            file_name="normalized_logs.csv",
            mime="text/csv",
        )

    else:
        st.warning("No recognizable cloud logs found.")
