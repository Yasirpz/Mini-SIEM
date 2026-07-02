"""
Seed Mini-SIEM with sample/synthetic data for a self-contained demo.

Creates:
- A sample monitored host (Lab-PC, 127.0.0.1, Linux)
- A suspicious test IP address in the Threat Intel registry
  (203.0.113.50 — reserved for documentation use per RFC 5737, so it is
  safe to use in demos and never routes to a real machine)
- A batch of synthetic failed-login / invalid-user events, archived to
  Parquet and run through the detection engine to produce alerts

Usage:
    python scripts/seed_sample_data.py
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.extensions import db
from app.models import Host, IPRegistry
from app.services.data_manager import DataManager
from app.services.log_analyzer import LogAnalyzer

SAMPLE_HOST = {"hostname": "Lab-PC", "ip_address": "127.0.0.1", "os_type": "LINUX"}
TEST_IP = "203.0.113.50"


def build_synthetic_events():
    now = datetime.now()
    events = [
        {
            "timestamp": now - timedelta(minutes=5),
            "alert_type": "FAILED_LOGIN",
            "source_ip": TEST_IP,
            "user": "root",
            "message": f"Failed password for root from {TEST_IP}",
            "raw_log": f"Failed password for root from {TEST_IP} port 51422 ssh2",
        },
        {
            "timestamp": now - timedelta(minutes=4),
            "alert_type": "FAILED_LOGIN",
            "source_ip": TEST_IP,
            "user": "root",
            "message": f"Failed password for root from {TEST_IP}",
            "raw_log": f"Failed password for root from {TEST_IP} port 51423 ssh2",
        },
        {
            "timestamp": now - timedelta(minutes=3),
            "alert_type": "INVALID_USER",
            "source_ip": TEST_IP,
            "user": "test",
            "message": f"Invalid user test from {TEST_IP}",
            "raw_log": f"Invalid user test from {TEST_IP} port 51424",
        },
        {
            "timestamp": now - timedelta(minutes=1),
            "alert_type": "FAILED_LOGIN",
            "source_ip": "198.51.100.23",
            "user": "admin",
            "message": "Failed password for admin from 198.51.100.23",
            "raw_log": "Failed password for admin from 198.51.100.23 port 51500 ssh2",
        },
    ]
    return events


def main():
    app = create_app()
    with app.app_context():
        # 1. Sample host
        host = Host.query.filter_by(ip_address=SAMPLE_HOST["ip_address"]).first()
        if not host:
            host = Host(**SAMPLE_HOST)
            db.session.add(host)
            db.session.commit()
            print(f"Created sample host '{host.hostname}' ({host.ip_address}).")
        else:
            print(f"Sample host '{host.hostname}' already exists.")

        # 2. Suspicious test IP
        if not IPRegistry.query.filter_by(ip_address=TEST_IP).first():
            db.session.add(IPRegistry(ip_address=TEST_IP, status="UNKNOWN"))
            db.session.commit()
            print(f"Added test IP {TEST_IP} to the Threat Intel registry (UNKNOWN).")
        else:
            print(f"Test IP {TEST_IP} already in the registry.")

        # 3. Synthetic events -> Parquet -> detection engine
        events = build_synthetic_events()
        filename, count = DataManager.save_logs_to_parquet(events, host.id)
        if not filename:
            print("No events were saved.")
            return
        print(f"Archived {count} synthetic events to storage/{filename}.")

        alerts_created = LogAnalyzer.analyze_parquet(filename, host.id)
        print(f"Detection engine generated {alerts_created} alert(s).")
        print("\nDone. Log in and open the dashboard to view the alerts.")


if __name__ == "__main__":
    main()
