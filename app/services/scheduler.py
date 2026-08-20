"""
Automatic log collection: the part that makes this a monitor rather than a
viewer.

Every collection in the system used to begin with a person pressing a button,
which meant nothing was ever noticed unless somebody was already looking. The
scheduler removes that dependency. It runs one background thread which wakes
at a fixed tick, asks the database which hosts are due, and calls the very
same `collect_host` pipeline the Collect button calls.

Design notes, since these were real choices rather than defaults:

*No third-party scheduler.* APScheduler or Celery would both do this job, and
a production deployment should probably use one. Neither is used here because
the whole system is designed to run on a laptop on an isolated lab network
with no internet access, and an extra dependency is one more thing that has to
be installed before a demonstration can start. The standard library's
threading module does what is needed in about a hundred lines.

*One tick job, not one job per host.* A job per host would have to be created,
rescheduled and cancelled every time a host was added, edited or deleted
through the API, and any missed update would leave a thread polling a host
that no longer exists. Instead a single tick re-reads the hosts each time and
asks each one whether it is due. The scheduler therefore holds no state that
can disagree with the database.

*Serial, not parallel.* Hosts are collected one after another. Collection
writes events, runs the detection rules and commits, and SQLite tolerates
concurrent writers poorly; the correctness of the alerting is worth far more
than the seconds saved by overlapping two collections.

*Failures are contained.* A host that cannot be reached is recorded as a
failed attempt by `collect_host` and the loop moves to the next one. Nothing a
single unreachable machine does may be allowed to kill the thread, because a
dead scheduler looks exactly like a quiet network.
"""
import logging
import threading

from app.models import Host, utcnow

log = logging.getLogger(__name__)


class CollectionScheduler:
    """A background thread that collects from every host that is due."""

    def __init__(self, app):
        self.app = app
        self.tick_seconds = max(
            int(app.config.get('SCHEDULER_TICK_SECONDS', 15)), 1
        )
        self._thread = None
        # Doubles as the shutdown signal and as the sleep: waiting on an Event
        # rather than calling sleep() means a stop request is acted on at once
        # instead of after the remainder of the current tick.
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.started_at = None
        self.last_tick = None
        self.ticks = 0
        self.collections = 0
        self.failures = 0

    # -- lifecycle ------------------------------------------------------

    def start(self):
        """Start the background thread, unless it is already running."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False

            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run,
                name='minisiem-collector',
                # A daemon thread does not keep the interpreter alive, so
                # Ctrl+C on the Flask server still exits promptly.
                daemon=True,
            )
            self.started_at = utcnow()
            self._thread.start()
            log.info(
                'Automatic collection started (tick every %ss)', self.tick_seconds
            )
            return True

    def stop(self, timeout=5):
        """Ask the thread to finish the current tick and exit."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        log.info('Automatic collection stopped')

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    # -- the loop -------------------------------------------------------

    def _run(self):
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                # Belt and braces: run_once already guards each host. This
                # catches anything raised by the query itself, so that a
                # transient database error cannot end the thread.
                log.exception('Collection tick failed')
            self._stop.wait(self.tick_seconds)

    def run_once(self):
        """
        Collect from every host that is currently due.

        Exposed separately from the loop so that it can be called directly by
        the tests and by the "Run now" control, without waiting for a tick.
        Returns the list of hostnames that were collected from.
        """
        collected = []

        with self.app.app_context():
            from app.extensions import db
            from app.services.collection import collect_host

            self.ticks += 1
            self.last_tick = utcnow()

            due = [
                host for host in Host.query.filter_by(polling_enabled=True).all()
                if host.poll_due()
            ]

            for host in due:
                # Stamped before the attempt, not after. If collection raises
                # or hangs, the host must still wait a full interval before it
                # is tried again — otherwise a permanently broken host would be
                # retried on every single tick.
                host.last_poll = utcnow()
                db.session.commit()

                try:
                    payload, status = collect_host(host)
                except Exception as exc:
                    self.failures += 1
                    log.exception(
                        'Automatic collection raised for %s', host.hostname
                    )
                    db.session.rollback()
                    host.record_attempt(False, error=f'Automatic collection failed: {exc}')
                    db.session.commit()
                    continue

                if status == 200:
                    self.collections += 1
                    collected.append(host.hostname)
                    log.info(
                        'Automatic collection from %s: %s',
                        host.hostname, payload.get('message'),
                    )
                else:
                    self.failures += 1
                    log.warning(
                        'Automatic collection from %s failed (%s): %s',
                        host.hostname, status, payload.get('error'),
                    )

        return collected

    # -- reporting ------------------------------------------------------

    def status(self):
        """A JSON-serialisable summary for the dashboard and the API."""
        from app.models import _fmt

        with self.app.app_context():
            polled = Host.query.filter_by(polling_enabled=True).all()
            next_due = min(
                (h.next_poll_at() for h in polled if h.next_poll_at()),
                default=None,
            )

            return {
                'running': self.running,
                'tick_seconds': self.tick_seconds,
                'started_at': _fmt(self.started_at),
                'last_tick': _fmt(self.last_tick),
                'ticks': self.ticks,
                'collections': self.collections,
                'failures': self.failures,
                'hosts_polled': len(polled),
                'next_poll': _fmt(next_due),
                'hosts': [
                    {
                        'id': h.id,
                        'hostname': h.hostname,
                        'interval_seconds': h.effective_poll_interval(),
                        'last_poll': _fmt(h.last_poll),
                        'next_poll': _fmt(h.next_poll_at()),
                    }
                    for h in polled
                ],
            }


def init_scheduler(app):
    """
    Attach a scheduler to the application and start it if configured to run.

    The instance is stored on the app either way, so the API can report an
    honest "not running" rather than pretending the feature is absent.
    """
    scheduler = CollectionScheduler(app)
    app.extensions['collection_scheduler'] = scheduler

    if not app.config.get('SCHEDULER_ENABLED', False):
        log.info('Automatic collection is disabled (SCHEDULER_ENABLED is false)')
        return scheduler

    if _is_reloader_parent(app):
        # Flask's debug reloader runs the app in two processes. Starting the
        # thread in both would collect from every host twice per interval and,
        # worse, would have two threads writing events concurrently.
        log.info('Skipping scheduler start in the reloader parent process')
        return scheduler

    scheduler.start()
    return scheduler


def get_scheduler(app):
    """The scheduler attached to an app, or None if init_scheduler never ran."""
    return app.extensions.get('collection_scheduler')


def _is_reloader_parent(app):
    """True in the outer process of Flask's debug auto-reloader."""
    import os

    return app.debug and os.environ.get('WERKZEUG_RUN_MAIN') != 'true'
