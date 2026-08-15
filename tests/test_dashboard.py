"""
TC-07 Dashboard Test (proposal Section 15).

Covers FR-08: the dashboard shows alerts and summary statistics.
"""
from app.services.log_analyzer import LogAnalyzer
from app.services.sample_loader import SampleLoader


def seed(host_id, attempts=8):
    """Import a synthetic burst so the dashboard has something to show."""
    events = SampleLoader.generate_synthetic(attempts=attempts)
    return LogAnalyzer.ingest(events, host_id, archive=False)


def test_summary_reports_counts(auth_client, host, banned_ip):
    seed(host.id)

    stats = auth_client.get('/api/stats/summary').get_json()

    assert stats['hosts'] == 1
    assert stats['events'] > 0
    assert stats['alerts'] > 0
    assert stats['high_alerts'] > 0     # the banned IP triggers R-03
    assert stats['banned_ips'] == 1
    assert stats['unacknowledged'] == stats['alerts']


def test_summary_is_zeroed_on_a_fresh_install(auth_client):
    stats = auth_client.get('/api/stats/summary').get_json()

    assert stats['hosts'] == 0
    assert stats['events'] == 0
    assert stats['alerts'] == 0


def test_severity_breakdown_covers_every_level(auth_client, host, banned_ip):
    seed(host.id)

    data = auth_client.get('/api/stats/severity').get_json()

    assert data['labels'] == ['LOW', 'MEDIUM', 'HIGH']
    assert len(data['counts']) == 3
    assert sum(data['counts']) > 0


def test_rule_breakdown_lists_every_rule(auth_client, host):
    seed(host.id)

    data = auth_client.get('/api/stats/rules').get_json()

    # R-01..R-04 detect attacks; R-05..R-08 cover post-compromise activity.
    assert len(data['labels']) == 8
    assert data['labels'][0].startswith('R-01')
    assert data['labels'][7].startswith('R-08')
    assert len(data['counts']) == len(data['labels'])


def test_timeline_returns_one_point_per_day(auth_client, host):
    seed(host.id)

    data = auth_client.get('/api/stats/timeline?days=7').get_json()

    assert len(data['labels']) == 7
    assert len(data['counts']) == 7
    # Today's bucket holds the synthetic burst, which is generated "now".
    assert data['counts'][-1] > 0


def test_timeline_day_count_is_clamped(auth_client):
    """A silly ?days= value must not produce an unbounded response."""
    data = auth_client.get('/api/stats/timeline?days=5000').get_json()
    assert len(data['labels']) == 90


def test_top_sources_ranks_attacking_ips(auth_client, host):
    seed(host.id)

    sources = auth_client.get('/api/stats/top-sources').get_json()

    assert len(sources) >= 1
    assert sources[0]['source_ip'] == '203.0.113.50'
    assert sources[0]['hits'] > 0
    # Results must be ordered by hit count, highest first.
    assert sources == sorted(sources, key=lambda s: s['hits'], reverse=True)


def test_dashboard_page_renders(auth_client, host):
    seed(host.id)

    response = auth_client.get('/')

    assert response.status_code == 200
    assert b'Security Dashboard' in response.data
    assert b'timelineChart' in response.data
    assert b'severityChart' in response.data


# ---------------------------------------------------------------- alert listing

def test_alerts_endpoint_returns_recent_alerts(auth_client, host):
    seed(host.id)

    alerts = auth_client.get('/api/alerts').get_json()

    assert isinstance(alerts, list)
    assert len(alerts) > 0
    assert 'severity' in alerts[0]


def test_alerts_can_be_filtered_by_severity(auth_client, host, banned_ip):
    seed(host.id)

    high = auth_client.get('/api/alerts?severity=HIGH&limit=200').get_json()

    assert len(high) > 0
    assert all(alert['severity'] == 'HIGH' for alert in high)


def test_alerts_can_be_filtered_by_rule(auth_client, host):
    seed(host.id)

    r02 = auth_client.get('/api/alerts?rule_id=R-02&limit=200').get_json()

    assert all(alert['rule_id'] == 'R-02' for alert in r02)


def test_invalid_severity_filter_is_rejected(auth_client):
    response = auth_client.get('/api/alerts?severity=CRITICAL')
    assert response.status_code == 400


def test_paginated_alerts_return_an_envelope(auth_client, host):
    seed(host.id)

    data = auth_client.get('/api/alerts?paginated=true&limit=2').get_json()

    assert 'total' in data
    assert len(data['alerts']) <= 2


def test_alert_can_be_acknowledged(auth_client, host):
    seed(host.id)
    alert_id = auth_client.get('/api/alerts').get_json()[0]['id']

    response = auth_client.post(f'/api/alerts/{alert_id}/acknowledge', json={})

    assert response.status_code == 200
    assert response.get_json()['acknowledged'] is True

    unreviewed = auth_client.get('/api/alerts?acknowledged=false&limit=200').get_json()
    assert all(alert['id'] != alert_id for alert in unreviewed)
