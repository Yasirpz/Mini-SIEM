from datetime import datetime, timezone
from app.extensions import db
from app.models import Alert, IPRegistry
from app.services.data_manager import DataManager


class LogAnalyzer:
    """
    Core of the SIEM: reads a Parquet log file and applies the detection
    rules (failed login, invalid user, threat-IP match) to raise alerts.
    """

    @staticmethod
    def analyze_parquet(filename, host_id):
        """Analyze a stored Parquet log file and create Alert rows. Returns alert count."""
        df = DataManager.load_logs(filename)

        if df.empty:
            return 0

        if 'alert_type' not in df.columns or 'source_ip' not in df.columns:
            return 0

        # Only login/authentication-related events are candidates for alerting
        attack_pattern = ['FAILED_LOGIN', 'INVALID_USER', 'WIN_FAILED_LOGIN']
        threats = df[df['alert_type'].isin(attack_pattern)]

        if threats.empty:
            return 0

        alerts_created = 0

        for _, row in threats.iterrows():
            ip = row['source_ip']

            # Threat Intelligence lookup (Rule R-03)
            ip_entry = IPRegistry.query.filter_by(ip_address=ip).first()
            if not ip_entry:
                # Unknown IP: register it for future correlation
                ip_entry = IPRegistry(ip_address=ip, status='UNKNOWN', last_seen=datetime.now(timezone.utc))
                db.session.add(ip_entry)
            else:
                ip_entry.last_seen = datetime.now(timezone.utc)

            # Default severity for failed login / invalid user events
            severity = 'WARNING'
            msg_prefix = ""

            if ip_entry.status == 'BANNED':
                severity = 'CRITICAL'
                msg_prefix = f"BANNED IP DETECTED: {ip} "
            elif ip_entry.status == 'TRUSTED':
                # Suppress alerts from explicitly trusted sources
                continue

            message = f"{msg_prefix}{row['message']}"
            new_alert = Alert(
                host_id=host_id,
                alert_type=row['alert_type'],
                source_ip=ip,
                severity=severity,
                message=message,
                timestamp=row['timestamp'],
            )

            db.session.add(new_alert)
            alerts_created += 1

        db.session.commit()
        return alerts_created
