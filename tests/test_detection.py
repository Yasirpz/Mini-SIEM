"""
TC-05 Log Analysis Test and TC-06 Alert Test (proposal Section 15).

Covers FR-06 (detect failed login, invalid user and suspicious IP patterns)
and FR-07 (generate alerts with severity, timestamp, host and source IP), by
exercising each of the four detection rules from Section 10.2 individually.
"""
from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.models import Alert, Event, IPRegistry
from app.services.detection import DetectionEngine
from app.services.log_analyzer import LogAnalyzer

ATTACKER_IP = '203.0.113.50'
OTHER_IP = '198.51.100.23'


def make_event(host_id, when, event_type='FAILED_LOGIN', ip=ATTACKER_IP, user='root'):
    """Insert a single event directly, bypassing the parsers."""
    event = Event(
        host_id=host_id,
        timestamp=when,
        event_type=event_type,
        source_ip=ip,
        username=user,
        message=f"{event_type} for {user} from {ip}",
        origin='TEST',
    )
    db.session.add(event)
    return event


@pytest.fixture
def base_time():
    """A fixed, whole-second reference point so window maths is exact."""
    return datetime(2026, 8, 12, 9, 0, 0)


# ================================================================ TC-05
# Log analysis: events are extracted from logs and stored.

def test_ingest_stores_events(app, host):
    from app.services.sample_loader import SampleLoader

    events = SampleLoader.generate_synthetic(attempts=8)
    result = LogAnalyzer.ingest(events, host.id, archive=False)

    assert result['events_received'] == len(events)
    assert result['events_stored'] == len(events)
    assert Event.query.count() == len(events)


def test_ingest_archives_to_parquet(app, host):
    from app.services.data_manager import DataManager
    from app.services.sample_loader import SampleLoader

    events = SampleLoader.generate_synthetic(attempts=4)
    result = LogAnalyzer.ingest(events, host.id, archive=True)

    assert result['archive_file'] is not None
    assert (DataManager.storage_dir() / result['archive_file']).exists()

    # The retained copy must be replayable.
    df = DataManager.load_logs(result['archive_file'])
    assert len(df) == len(events)


def test_reingesting_the_same_logs_does_not_duplicate_events(app, host):
    from app.services.sample_loader import SampleLoader

    events = SampleLoader.generate_synthetic(attempts=6)

    first = LogAnalyzer.ingest(events, host.id, archive=False)
    second = LogAnalyzer.ingest(events, host.id, archive=False)

    assert second['events_stored'] == 0
    assert second['duplicates_skipped'] == first['events_stored']
    assert Event.query.count() == first['events_stored']


# ================================================================ TC-06 / R-01
# Failed Login Rule: repeated failures for the same user/IP in a short window.

def test_r01_fires_on_a_burst_of_failed_logins(app, host, base_time):
    # Six failures inside three minutes — over the default threshold of five.
    for minute in range(6):
        make_event(host.id, base_time + timedelta(seconds=30 * minute))
    db.session.commit()

    counts = DetectionEngine.run()

    assert counts['R-01'] == 1
    alert = Alert.query.filter_by(rule_id='R-01').one()
    assert alert.severity == 'MEDIUM'
    assert alert.source_ip == ATTACKER_IP
    assert alert.host_id == host.id


def test_r01_does_not_fire_below_the_threshold(app, host, base_time):
    """Four failures is under the threshold of five — no alert."""
    for minute in range(4):
        make_event(host.id, base_time + timedelta(seconds=30 * minute))
    db.session.commit()

    counts = DetectionEngine.run()
    assert counts['R-01'] == 0


def test_r01_does_not_fire_when_failures_are_spread_beyond_the_window(app, host, base_time):
    """
    Six failures an hour apart are a user forgetting a password, not a burst.
    This is what distinguishes R-01 from alerting on every single failure.
    """
    for hour in range(6):
        make_event(host.id, base_time + timedelta(hours=hour))
    db.session.commit()

    counts = DetectionEngine.run()
    assert counts['R-01'] == 0


def test_r01_raises_one_alert_per_burst_not_per_event(app, host, base_time):
    for index in range(10):
        make_event(host.id, base_time + timedelta(seconds=20 * index))
    db.session.commit()

    counts = DetectionEngine.run()
    assert counts['R-01'] == 1


def test_r01_is_idempotent_across_repeated_runs(app, host, base_time):
    """Re-running detection must not duplicate existing alerts."""
    for index in range(6):
        make_event(host.id, base_time + timedelta(seconds=30 * index))
    db.session.commit()

    first = DetectionEngine.run()
    second = DetectionEngine.run()

    assert first['R-01'] == 1
    assert second['R-01'] == 0
    assert Alert.query.filter_by(rule_id='R-01').count() == 1


def test_r01_separates_different_usernames(app, host, base_time):
    """Five failures each for two users are two separate bursts."""
    for index in range(5):
        make_event(host.id, base_time + timedelta(seconds=20 * index), user='root')
    for index in range(5):
        make_event(host.id, base_time + timedelta(seconds=20 * index), user='admin')
    db.session.commit()

    counts = DetectionEngine.run()
    assert counts['R-01'] == 2


# ================================================================ TC-06 / R-02
# Invalid User Rule.

def test_r02_fires_for_an_invalid_user_attempt(app, host, base_time):
    make_event(host.id, base_time, event_type='INVALID_USER', user='oracle')
    db.session.commit()

    counts = DetectionEngine.run()

    assert counts['R-02'] == 1
    alert = Alert.query.filter_by(rule_id='R-02').one()
    assert alert.severity == 'LOW'
    assert 'oracle' in alert.message
    assert alert.source_ip == ATTACKER_IP


def test_r02_ignores_ordinary_failed_logins(app, host, base_time):
    make_event(host.id, base_time, event_type='FAILED_LOGIN')
    db.session.commit()

    counts = DetectionEngine.run()
    assert counts['R-02'] == 0


# ================================================================ TC-06 / R-03
# Threat IP Match Rule.

def test_r03_fires_for_a_banned_source_ip(app, host, banned_ip, base_time):
    make_event(host.id, base_time)
    db.session.commit()

    counts = DetectionEngine.run()

    assert counts['R-03'] == 1
    alert = Alert.query.filter_by(rule_id='R-03').one()
    assert alert.severity == 'HIGH'
    assert alert.source_ip == ATTACKER_IP


def test_r03_does_not_fire_for_an_unlisted_ip(app, host, base_time):
    make_event(host.id, base_time)
    db.session.commit()

    counts = DetectionEngine.run()
    assert counts['R-03'] == 0


def test_r03_escalates_after_the_ip_is_banned(app, host, base_time):
    """
    The demonstration flow: import logs, see medium alerts, mark the source
    BANNED, re-run detection, and watch severity escalate to HIGH.
    """
    for index in range(6):
        make_event(host.id, base_time + timedelta(seconds=30 * index))
    db.session.commit()

    before = DetectionEngine.run()
    assert before['R-03'] == 0
    assert Alert.query.filter_by(severity='HIGH').count() == 0

    # The first run auto-registered the address as UNKNOWN, so promote that
    # existing row rather than inserting a second one.
    entry = IPRegistry.query.filter_by(ip_address=ATTACKER_IP).one()
    assert entry.status == 'UNKNOWN'
    entry.status = 'BANNED'
    db.session.commit()

    after = DetectionEngine.run()
    assert after['R-03'] == 6
    assert Alert.query.filter_by(severity='HIGH').count() == 6


def test_trusted_ip_suppresses_alerts(app, host, base_time):
    """An explicitly trusted source should not generate noise."""
    db.session.add(IPRegistry(ip_address=ATTACKER_IP, status='TRUSTED'))
    for index in range(6):
        make_event(host.id, base_time + timedelta(seconds=30 * index))
    db.session.commit()

    counts = DetectionEngine.run()
    assert counts['total'] == 0


# ================================================================ TC-06 / R-04
# Multiple Host Attempt Rule.

def test_r04_fires_when_one_ip_attacks_two_hosts(app, two_hosts, base_time):
    first, second = two_hosts
    make_event(first.id, base_time)
    make_event(second.id, base_time + timedelta(minutes=1))
    db.session.commit()

    counts = DetectionEngine.run()

    assert counts['R-04'] == 1
    alert = Alert.query.filter_by(rule_id='R-04').one()
    assert alert.severity == 'HIGH'
    assert alert.source_ip == ATTACKER_IP
    assert 'different monitored hosts' in alert.message


def test_r04_does_not_fire_for_a_single_host(app, host, base_time):
    for index in range(6):
        make_event(host.id, base_time + timedelta(seconds=30 * index))
    db.session.commit()

    counts = DetectionEngine.run()
    assert counts['R-04'] == 0


def test_r04_still_correlates_when_analysis_is_scoped_to_one_host(app, two_hosts, base_time):
    """
    Correlating one IP across machines is the point of R-04, so it must look
    beyond the host the caller asked about.
    """
    first, second = two_hosts
    make_event(first.id, base_time)
    make_event(second.id, base_time + timedelta(minutes=1))
    db.session.commit()

    counts = DetectionEngine.run(host_id=first.id)
    assert counts['R-04'] == 1


# ================================================================ registry upkeep

def test_unseen_source_ips_are_auto_registered(app, host, base_time):
    make_event(host.id, base_time, ip=OTHER_IP)
    db.session.commit()

    DetectionEngine.run()

    entry = IPRegistry.query.filter_by(ip_address=OTHER_IP).one()
    assert entry.status == 'UNKNOWN'
    assert entry.hit_count == 1


def test_local_console_events_do_not_pollute_the_registry(app, host, base_time):
    """'LOCAL' is a marker, not a routable attacker address."""
    make_event(host.id, base_time, ip='LOCAL')
    make_event(host.id, base_time, event_type='WIN_FAILED_LOGIN', ip='LOCAL_CONSOLE')
    db.session.commit()

    DetectionEngine.run()
    assert IPRegistry.query.count() == 0


# ================================================================ alert fields

def test_alerts_carry_every_required_field(app, host, banned_ip, base_time):
    """FR-07: severity, timestamp, host and source IP must all be present."""
    make_event(host.id, base_time)
    db.session.commit()
    DetectionEngine.run()

    alert = Alert.query.first()
    assert alert.severity in ('LOW', 'MEDIUM', 'HIGH')
    assert alert.timestamp is not None
    assert alert.host_id == host.id
    assert alert.source_ip == ATTACKER_IP
    assert alert.rule_id is not None
    assert alert.message
    assert alert.acknowledged is False
