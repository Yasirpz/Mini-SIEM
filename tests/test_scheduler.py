"""
Automatic (scheduled) log collection.

The scheduler is the difference between a log viewer and a monitor, so what
is tested here is mostly *when* it decides to collect rather than how the
collection itself works — that is covered by the collection tests. The rules
it has to get right are: never poll a host that was not asked for, never poll
one more often than its interval, never let one broken host stop the rest,
and never leave a failing host retrying on every single tick.
"""
from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    Host,
    MIN_POLL_INTERVAL_SECONDS,
    utcnow,
)
from app.services.scheduler import CollectionScheduler


@pytest.fixture
def scheduler(app):
    """A scheduler bound to the test app, driven by hand rather than by a thread."""
    return CollectionScheduler(app)


def _host(hostname='Lab-PC', ip='192.168.100.90', **kwargs):
    host = Host(hostname=hostname, ip_address=ip, os_type='WINDOWS', **kwargs)
    db.session.add(host)
    db.session.commit()
    return host


def _collect_calls(monkeypatch, outcome=({'message': 'ok'}, 200)):
    """Replace the collection pipeline and record which hosts it was given."""
    calls = []

    def fake_collect(host):
        calls.append(host.hostname)
        return outcome

    import app.services.collection as collection_service
    monkeypatch.setattr(collection_service, 'collect_host', fake_collect)
    return calls


# ---------------------------------------------------------------------------
# When a host is due
# ---------------------------------------------------------------------------

def test_a_host_is_not_polled_unless_it_was_asked_for(app):
    """
    Polling is opt-in. Upgrading an existing installation must not silently
    start making authenticated connections to machines on the network.
    """
    host = _host()

    assert host.polling_enabled is False
    assert host.next_poll_at() is None
    assert host.poll_due() is False


def test_enabling_polling_makes_a_host_due_immediately(app):
    """
    Someone who has just switched the toggle on is watching for something to
    happen. Making them wait a full interval to find out whether it works
    would look indistinguishable from it being broken.
    """
    host = _host(polling_enabled=True)

    assert host.last_poll is None
    assert host.poll_due() is True


def test_a_recently_polled_host_waits_for_its_interval(app):
    host = _host(polling_enabled=True, poll_interval_seconds=300)
    host.last_poll = utcnow()
    db.session.commit()

    assert host.poll_due() is False
    assert host.poll_due(now=utcnow() + timedelta(seconds=299)) is False
    assert host.poll_due(now=utcnow() + timedelta(seconds=301)) is True


def test_the_interval_falls_back_to_the_shared_default(app):
    host = _host(polling_enabled=True)
    assert host.effective_poll_interval() == DEFAULT_POLL_INTERVAL_SECONDS


def test_an_implausibly_short_interval_is_clamped(app):
    """
    A value this small can only come from a hand-edited database. Honouring it
    would start the next collection before the previous one had finished.
    """
    host = _host(polling_enabled=True, poll_interval_seconds=1)
    assert host.effective_poll_interval() == MIN_POLL_INTERVAL_SECONDS


# ---------------------------------------------------------------------------
# What a tick actually does
# ---------------------------------------------------------------------------

def test_a_tick_collects_from_a_due_host(app, scheduler, monkeypatch):
    _host(polling_enabled=True)
    calls = _collect_calls(monkeypatch)

    collected = scheduler.run_once()

    assert calls == ['Lab-PC']
    assert collected == ['Lab-PC']
    assert scheduler.collections == 1


def test_a_tick_ignores_hosts_that_are_not_polling(app, scheduler, monkeypatch):
    _host('Watched', '192.168.100.91', polling_enabled=True)
    _host('Ignored', '192.168.100.92', polling_enabled=False)
    calls = _collect_calls(monkeypatch)

    scheduler.run_once()

    assert calls == ['Watched']


def test_a_second_tick_does_not_collect_again_straight_away(app, scheduler, monkeypatch):
    """The tick runs far more often than any host's interval, by design."""
    _host(polling_enabled=True, poll_interval_seconds=300)
    calls = _collect_calls(monkeypatch)

    scheduler.run_once()
    scheduler.run_once()
    scheduler.run_once()

    assert calls == ['Lab-PC']


def test_the_poll_clock_advances_even_when_collection_fails(app, scheduler, monkeypatch):
    """
    A host that cannot be reached must wait its full interval like any other.
    Retrying a broken host on every tick would flood the log and hammer a
    machine that is probably already having a bad day.
    """
    _host(polling_enabled=True, poll_interval_seconds=300)
    calls = _collect_calls(monkeypatch, outcome=({'error': 'unreachable'}, 502))

    scheduler.run_once()
    scheduler.run_once()

    assert calls == ['Lab-PC']
    assert scheduler.failures == 1
    assert scheduler.collections == 0


def test_one_broken_host_does_not_stop_the_others(app, scheduler, monkeypatch):
    """
    The loop must survive an exception from the pipeline. A scheduler that
    dies looks exactly like a network where nothing is happening.
    """
    _host('Broken', '192.168.100.93', polling_enabled=True)
    _host('Working', '192.168.100.94', polling_enabled=True)

    seen = []

    def fake_collect(host):
        seen.append(host.hostname)
        if host.hostname == 'Broken':
            raise RuntimeError('WinRM exploded')
        return {'message': 'ok'}, 200

    import app.services.collection as collection_service
    monkeypatch.setattr(collection_service, 'collect_host', fake_collect)

    scheduler.run_once()

    assert sorted(seen) == ['Broken', 'Working']
    assert scheduler.collections == 1
    assert scheduler.failures == 1


def test_a_failed_automatic_collection_is_recorded_against_the_host(app, scheduler, monkeypatch):
    """An operator must be able to see why a host stopped reporting."""
    host = _host(polling_enabled=True)

    def explode(host):
        raise RuntimeError('WinRM exploded')

    import app.services.collection as collection_service
    monkeypatch.setattr(collection_service, 'collect_host', explode)

    scheduler.run_once()

    refreshed = db.session.get(Host, host.id)
    assert refreshed.last_error is not None
    assert 'WinRM exploded' in refreshed.last_error


# ---------------------------------------------------------------------------
# The API surface
# ---------------------------------------------------------------------------

def test_polling_can_be_switched_on_through_the_api(auth_client, app):
    host = _host()

    response = auth_client.put(
        f'/api/hosts/{host.id}',
        json={'polling_enabled': True, 'poll_interval_seconds': 60},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['polling_enabled'] is True
    assert payload['poll_interval_seconds'] == 60
    assert payload['poll_interval_effective'] == 60
    assert payload['next_poll']


def test_an_interval_below_the_minimum_is_rejected(auth_client, app):
    host = _host()

    response = auth_client.put(
        f'/api/hosts/{host.id}', json={'poll_interval_seconds': 5}
    )

    assert response.status_code == 400
    assert 'at least' in response.get_json()['error']


def test_a_nonsense_interval_is_rejected(auth_client, app):
    host = _host()

    response = auth_client.put(
        f'/api/hosts/{host.id}', json={'poll_interval_seconds': 'soon'}
    )

    assert response.status_code == 400


def test_the_scheduler_status_is_reported(auth_client, app):
    _host(polling_enabled=True)

    response = auth_client.get('/api/scheduler')

    assert response.status_code == 200
    payload = response.get_json()
    # The test configuration deliberately leaves the thread unstarted.
    assert payload['running'] is False
    assert payload['enabled'] is False
    assert payload['hosts_polled'] == 1
    assert payload['hosts'][0]['hostname'] == 'Lab-PC'


def test_the_scheduler_status_needs_a_login(client, app):
    assert client.get('/api/scheduler').status_code == 401


def test_run_now_collects_without_waiting_for_the_timer(auth_client, app, monkeypatch):
    _host(polling_enabled=True)
    calls = _collect_calls(monkeypatch)

    response = auth_client.post('/api/scheduler/run')

    assert response.status_code == 200
    assert calls == ['Lab-PC']
    assert response.get_json()['collected'] == ['Lab-PC']


def test_run_now_says_so_when_nothing_is_due(auth_client, app, monkeypatch):
    _host(polling_enabled=False)
    calls = _collect_calls(monkeypatch)

    response = auth_client.post('/api/scheduler/run')

    assert response.status_code == 200
    assert calls == []
    assert 'No host was due' in response.get_json()['message']


# ---------------------------------------------------------------------------
# The thread itself
# ---------------------------------------------------------------------------

def test_the_thread_starts_and_stops_cleanly(app, scheduler):
    assert scheduler.running is False
    assert scheduler.start() is True
    assert scheduler.running is True

    # A second start must not create a second thread collecting in parallel.
    assert scheduler.start() is False

    scheduler.stop()
    assert scheduler.running is False


def test_the_scheduler_is_not_started_by_the_test_configuration(app):
    """
    Tests drive the scheduler explicitly. A thread ticking away against an
    in-memory database that the fixture is about to drop would produce
    failures that had nothing to do with the test being run.
    """
    from app.services.scheduler import get_scheduler

    assert app.config['SCHEDULER_ENABLED'] is False
    assert get_scheduler(app).running is False


def test_a_host_with_no_preference_reports_the_default_without_storing_it(auth_client, app):
    """
    The stored value and the value in use are reported separately, so opening
    and saving a host in the interface cannot silently pin it to whatever the
    default happened to be that day.
    """
    host = _host()

    payload = auth_client.get('/api/hosts').get_json()[0]

    assert payload['poll_interval_seconds'] is None
    assert payload['poll_interval_effective'] == DEFAULT_POLL_INTERVAL_SECONDS
    assert host.poll_interval_seconds is None
