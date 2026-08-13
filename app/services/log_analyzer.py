"""
Log Analysis Module (proposal Section 11).

Takes normalized log events from any source — SSH collection, Windows Event
Log collection, an imported sample file, or generated synthetic data — and
runs them through the standard pipeline:

    archive to Parquet  ->  store as Event rows  ->  apply detection rules

Keeping the pipeline in one place means every log source behaves identically,
so an imported sample file produces exactly the same alerts as a live
collection would.
"""
from datetime import datetime, timezone

import pandas as pd

from app.extensions import db
from app.models import Event, LogArchive, utcnow
from app.services.data_manager import DataManager
from app.services.detection import DetectionEngine

# Columns every normalized event dict is expected to carry.
EVENT_FIELDS = ('timestamp', 'alert_type', 'source_ip', 'user', 'message', 'raw_log')


class LogAnalyzer:

    @staticmethod
    def ingest(events, host_id, origin='COLLECTED', archive=True):
        """
        Run a batch of normalized event dicts through the full pipeline.

        Args:
            events:  list of dicts with the EVENT_FIELDS keys.
            host_id: the monitored host these events belong to.
            origin:  COLLECTED, IMPORTED or SYNTHETIC — recorded on each event
                     so the dashboard can distinguish demo data from live data.
            archive: write a Parquet copy for forensic retention.

        Returns a summary dict describing what was stored and detected.
        """
        if not events:
            return {
                'events_received': 0,
                'events_stored': 0,
                'duplicates_skipped': 0,
                'archive_file': None,
                'alerts': {'R-01': 0, 'R-02': 0, 'R-03': 0, 'R-04': 0, 'total': 0},
            }

        archive_file = None
        if archive:
            archive_file, record_count = DataManager.save_logs_to_parquet(events, host_id)
            if archive_file:
                db.session.add(
                    LogArchive(
                        host_id=host_id,
                        filename=archive_file,
                        record_count=record_count,
                        origin=origin,
                    )
                )
                db.session.commit()

        stored, skipped = LogAnalyzer.store_events(events, host_id, origin=origin)
        alerts = DetectionEngine.run()

        return {
            'events_received': len(events),
            'events_stored': stored,
            'duplicates_skipped': skipped,
            'archive_file': archive_file,
            'alerts': alerts,
        }

    @staticmethod
    def store_events(events, host_id, origin='COLLECTED'):
        """
        Persist normalized event dicts as Event rows.

        Collectors fetch by time window, so the same log line can legitimately
        arrive twice. Events are therefore de-duplicated on the natural key
        (host, timestamp, type, source IP, username).

        Returns (stored_count, duplicates_skipped).
        """
        existing = {
            (e.timestamp, e.event_type, e.source_ip, e.username)
            for e in Event.query.filter_by(host_id=host_id).all()
        }

        stored = 0
        skipped = 0

        for raw in events:
            timestamp = _normalize_timestamp(raw.get('timestamp'))
            event_type = raw.get('alert_type')
            source_ip = _clean(raw.get('source_ip'))
            username = _clean(raw.get('user'))

            key = (timestamp, event_type, source_ip, username)
            if key in existing:
                skipped += 1
                continue

            db.session.add(
                Event(
                    host_id=host_id,
                    timestamp=timestamp,
                    event_type=event_type,
                    source_ip=source_ip,
                    username=username,
                    message=_clean(raw.get('message')),
                    raw_log=_clean(raw.get('raw_log')),
                    origin=origin,
                    ingested_at=utcnow(),
                )
            )
            existing.add(key)
            stored += 1

        db.session.commit()
        return stored, skipped

    @staticmethod
    def analyze_parquet(filename, host_id, origin='COLLECTED'):
        """
        Re-process an archived Parquet file through the pipeline.

        Used to replay retained evidence without contacting the host again.
        Returns the number of alerts created.
        """
        df = DataManager.load_logs(filename)
        if df.empty:
            return 0

        events = df.to_dict(orient='records')
        result = LogAnalyzer.ingest(events, host_id, origin=origin, archive=False)
        return result['alerts']['total']


def _normalize_timestamp(value):
    """
    Coerce whatever a log source produced into a naive UTC datetime.

    Parquet round-trips give pandas Timestamps, importers give strings, and
    collectors give datetimes — all three land here.
    """
    # pandas NaT subclasses datetime, so it has to be rejected before the
    # isinstance checks below would happily accept it.
    if value is None or value is pd.NaT:
        return utcnow()

    if isinstance(value, pd.Timestamp):
        value = value.to_pydatetime()
    elif isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return utcnow()

    if not isinstance(value, datetime):
        return utcnow()

    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)

    # Drop sub-second precision so de-duplication keys compare reliably
    # across a Parquet round-trip.
    return value.replace(microsecond=0)


def _clean(value):
    """Turn pandas NaN/NaT and empty values into None, otherwise stringify."""
    if value is None:
        return None

    if not isinstance(value, (str, bytes)):
        try:
            if pd.isna(value):
                return None
        except (TypeError, ValueError):
            pass  # arrays and other odd types aren't missing values

    text = str(value).strip()
    return text or None
