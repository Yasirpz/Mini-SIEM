"""
Rule-based detection engine.

Implements the four core detection rules defined in Section 10.2 of the
project proposal:

    R-01  Failed Login Rule          repeated auth failures for the same
                                     user/IP inside a short time window
    R-02  Invalid User Rule          login attempts for a non-existent user
    R-03  Threat IP Match Rule       source IP is BANNED in the registry
    R-04  Multiple Host Attempt Rule same source IP attacking several hosts

Later rules extend the same engine to post-compromise and physical activity:
up to R-09 (an external storage device connected to a monitored machine) and
R-10 (a file under integrity monitoring stopped matching its baseline).

The engine runs over Event rows that are already stored in the database, so
rules can be re-applied at any time without re-collecting logs. Every alert is
anchored to the Event that triggered it, and the engine refuses to create a
second alert for the same (rule, event) pair — meaning a re-run is idempotent
and will not flood the dashboard with duplicates.
"""
from collections import defaultdict
from datetime import timedelta

from flask import current_app

from app.extensions import db
from app.models import (
    Alert,
    Event,
    IPRegistry,
    FAILURE_EVENT_TYPES,
    EVT_ACCOUNT_CREATED,
    EVT_ACCOUNT_DELETED,
    EVT_ACCOUNT_LOCKOUT,
    EVT_AUDIT_LOG_CLEARED,
    EVT_GROUP_MEMBER_ADDED,
    EVT_PASSWORD_RESET,
    EVT_INVALID_USER,
    EVT_FILE_ADDED,
    EVT_FILE_DELETED,
    EVT_FILE_MODIFIED,
    EVT_USB_DEVICE_CONNECTED,
    IP_BANNED,
    IP_TRUSTED,
    IP_UNKNOWN,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    utcnow,
)

# Source IPs that never represent a remote attacker and would only create noise.
NON_ROUTABLE_MARKERS = {'LOCAL', 'LOCAL_CONSOLE', '-', '', None}

# Default thresholds. Overridable via config so they can be tuned for a demo.
DEFAULT_FAILED_LOGIN_THRESHOLD = 5
DEFAULT_FAILED_LOGIN_WINDOW_MINUTES = 10
DEFAULT_MULTI_HOST_THRESHOLD = 2


class RuleResult:
    """A candidate alert produced by a rule, before de-duplication."""

    def __init__(self, rule_id, event, severity, alert_type, message, host_id=None):
        self.rule_id = rule_id
        self.event = event
        self.severity = severity
        self.alert_type = alert_type
        self.message = message
        self.host_id = host_id if host_id is not None else event.host_id


class DetectionEngine:
    """Applies the R-01..R-10 rules to stored events and writes Alert rows."""

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    @staticmethod
    def run(host_id=None, since=None):
        """
        Apply every detection rule and persist the resulting alerts.

        Args:
            host_id: restrict analysis to a single host, or None for all hosts.
                     R-04 always looks across all hosts, since correlating one
                     IP across several machines is the whole point of the rule.
            since:   only consider events at or after this datetime.

        Returns a dict of {rule_id: alerts_created} plus a 'total' key.
        """
        query = Event.query
        if host_id is not None:
            query = query.filter(Event.host_id == host_id)
        if since is not None:
            query = query.filter(Event.timestamp >= since)

        events = query.order_by(Event.timestamp.asc()).all()

        # R-04 correlates across hosts, so it needs the full picture even when
        # the caller asked for a single host.
        if host_id is None:
            all_events = events
        else:
            all_query = Event.query
            if since is not None:
                all_query = all_query.filter(Event.timestamp >= since)
            all_events = all_query.order_by(Event.timestamp.asc()).all()

        DetectionEngine._refresh_registry(events)

        candidates = []
        candidates.extend(DetectionEngine.rule_01_failed_login(events))
        candidates.extend(DetectionEngine.rule_02_invalid_user(events))
        candidates.extend(DetectionEngine.rule_03_threat_ip(events))
        candidates.extend(DetectionEngine.rule_04_multiple_hosts(all_events))
        candidates.extend(DetectionEngine.rule_05_audit_log_cleared(events))
        candidates.extend(DetectionEngine.rule_06_account_created(events))
        candidates.extend(DetectionEngine.rule_07_privilege_change(events))
        candidates.extend(DetectionEngine.rule_08_lockout(events))
        candidates.extend(DetectionEngine.rule_09_external_device(events))
        candidates.extend(DetectionEngine.rule_10_file_integrity(events))

        return DetectionEngine._persist(candidates)

    # ------------------------------------------------------------------
    # R-01: repeated failed logins in a short window
    # ------------------------------------------------------------------

    @staticmethod
    def rule_01_failed_login(events):
        """
        Group authentication failures by (host, source, username) and raise an
        alert when the count reaches the threshold inside the time window.

        A sliding window is used so that a slow trickle of failures spread over
        hours does not trigger, but a burst does.

        Failures at the machine's own keyboard count. They used to be dropped
        along with everything else carrying a LOCAL or LOCAL_CONSOLE marker,
        on the reasoning that those are not attacker addresses -- which is
        correct for R-03 and R-04, where the whole question is *which remote
        address* is responsible, and wrong here. Somebody standing at a lab PC
        trying passwords is exactly what this rule is for, and on a lab bench
        it is the likeliest form the attack takes. The consequence was that a
        monitored Windows machine could record twenty-one failed logons and
        raise nothing at all.

        The marker is used as the grouping key in place of an address, so the
        rule's shape is unchanged: still one alert per (host, source, user)
        burst, still the same threshold and window.
        """
        threshold = _config('DETECTION_FAILED_LOGIN_THRESHOLD', DEFAULT_FAILED_LOGIN_THRESHOLD)
        window = timedelta(
            minutes=_config(
                'DETECTION_FAILED_LOGIN_WINDOW_MINUTES', DEFAULT_FAILED_LOGIN_WINDOW_MINUTES
            )
        )

        groups = defaultdict(list)
        for event in events:
            if event.event_type not in FAILURE_EVENT_TYPES:
                continue
            # Deliberately no _is_non_routable check -- see the docstring.
            # A missing source is normalised so that failures arriving with
            # None and with an empty string are not counted as two separate
            # attackers of one attempt each.
            source = event.source_ip or 'LOCAL_CONSOLE'
            groups[(event.host_id, source, event.username)].append(event)

        results = []
        for (host_id, source_ip, username), group in groups.items():
            group.sort(key=lambda e: e.timestamp)

            start = 0
            for end in range(len(group)):
                # Shrink the window from the left until it spans <= `window`.
                while group[end].timestamp - group[start].timestamp > window:
                    start += 1

                count = end - start + 1
                if count < threshold:
                    continue

                # Anchor to the event that completed the burst. Later events in
                # the same burst keep re-triggering, but de-duplication in
                # _persist collapses them to one alert per anchor event.
                anchor = group[end]
                results.append(
                    RuleResult(
                        rule_id='R-01',
                        event=anchor,
                        severity=SEVERITY_MEDIUM,
                        alert_type='REPEATED_FAILED_LOGIN',
                        message=(
                            f"{count} failed login attempts for user "
                            f"'{username or 'unknown'}' {_describe_source(source_ip)} "
                            f"within {int(window.total_seconds() // 60)} minutes."
                        ),
                        host_id=host_id,
                    )
                )
                # One alert per burst: stop scanning this group once it fires.
                break

        return results

    # ------------------------------------------------------------------
    # R-02: invalid user attempts
    # ------------------------------------------------------------------

    @staticmethod
    def rule_02_invalid_user(events):
        """Raise a low-severity alert for each attempt to log in as a user that does not exist."""
        results = []
        for event in events:
            if event.event_type != EVT_INVALID_USER:
                continue

            results.append(
                RuleResult(
                    rule_id='R-02',
                    event=event,
                    severity=SEVERITY_LOW,
                    alert_type='INVALID_USER',
                    message=(
                        f"Login attempt for non-existent user "
                        f"'{event.username or 'unknown'}' from "
                        f"{event.source_ip or 'unknown source'}."
                    ),
                )
            )
        return results

    # ------------------------------------------------------------------
    # R-03: source IP is banned in the Threat Intelligence registry
    # ------------------------------------------------------------------

    @staticmethod
    def rule_03_threat_ip(events):
        """Raise a high-severity alert for any event whose source IP is marked BANNED."""
        banned = {
            entry.ip_address
            for entry in IPRegistry.query.filter_by(status=IP_BANNED).all()
        }
        if not banned:
            return []

        results = []
        for event in events:
            if event.source_ip not in banned:
                continue

            results.append(
                RuleResult(
                    rule_id='R-03',
                    event=event,
                    severity=SEVERITY_HIGH,
                    alert_type='THREAT_IP_MATCH',
                    message=(
                        f"Event from BANNED IP {event.source_ip} "
                        f"(user '{event.username or 'unknown'}', "
                        f"type {event.event_type})."
                    ),
                )
            )
        return results

    # ------------------------------------------------------------------
    # R-04: same source IP seen attacking multiple hosts
    # ------------------------------------------------------------------

    @staticmethod
    def rule_04_multiple_hosts(events):
        """
        Correlate authentication failures by source IP across hosts.

        An IP that fails against several different machines is far more likely
        to be a scan or a spray than a user who forgot their password, so this
        escalates to high severity.
        """
        threshold = _config('DETECTION_MULTI_HOST_THRESHOLD', DEFAULT_MULTI_HOST_THRESHOLD)

        hosts_by_ip = defaultdict(set)
        latest_by_ip = {}

        for event in events:
            if event.event_type not in FAILURE_EVENT_TYPES:
                continue
            if _is_non_routable(event.source_ip):
                continue

            hosts_by_ip[event.source_ip].add(event.host_id)
            known = latest_by_ip.get(event.source_ip)
            if known is None or event.timestamp >= known.timestamp:
                latest_by_ip[event.source_ip] = event

        results = []
        for source_ip, host_ids in hosts_by_ip.items():
            if len(host_ids) < threshold:
                continue

            anchor = latest_by_ip[source_ip]
            results.append(
                RuleResult(
                    rule_id='R-04',
                    event=anchor,
                    severity=SEVERITY_HIGH,
                    alert_type='MULTI_HOST_ATTEMPT',
                    message=(
                        f"Source IP {source_ip} produced authentication failures on "
                        f"{len(host_ids)} different monitored hosts."
                    ),
                )
            )
        return results

    # ------------------------------------------------------------------
    # R-05: the audit log was cleared
    # ------------------------------------------------------------------

    @staticmethod
    def rule_05_audit_log_cleared(events):
        """
        Clearing the Security log destroys the evidence a SIEM depends on.

        It has essentially no legitimate cause on a monitored machine, so it
        is treated as high severity with no threshold: one occurrence is the
        whole signal.
        """
        return [
            RuleResult(
                rule_id='R-05',
                event=event,
                severity=SEVERITY_HIGH,
                alert_type='AUDIT_LOG_CLEARED',
                message=(
                    f"The Windows Security audit log was cleared by "
                    f"'{event.username or 'unknown'}'. This destroys evidence and "
                    f"is rarely legitimate."
                ),
            )
            for event in events
            if event.event_type == EVT_AUDIT_LOG_CLEARED
        ]

    # ------------------------------------------------------------------
    # R-06: a new account appeared, or an existing one was removed
    # ------------------------------------------------------------------

    @staticmethod
    def rule_06_account_created(events):
        """
        Account creation and deletion are how an intruder establishes
        persistence or covers their tracks. Both are legitimate
        administrative actions too, so this is medium rather than high: it
        asks the administrator to confirm it was expected.
        """
        results = []
        for event in events:
            if event.event_type == EVT_ACCOUNT_CREATED:
                action = 'created'
            elif event.event_type == EVT_ACCOUNT_DELETED:
                action = 'deleted'
            else:
                continue

            results.append(
                RuleResult(
                    rule_id='R-06',
                    event=event,
                    severity=SEVERITY_MEDIUM,
                    alert_type='ACCOUNT_CHANGE',
                    message=(
                        f"Windows account '{event.username or 'unknown'}' was "
                        f"{action}. Confirm this was an expected administrative "
                        f"action."
                    ),
                )
            )
        return results

    # ------------------------------------------------------------------
    # R-07: privileges were widened
    # ------------------------------------------------------------------

    @staticmethod
    def rule_07_privilege_change(events):
        """
        Group membership changes and password resets are the classic
        privilege-escalation and account-takeover steps.

        Plain administrative logons (4672) are deliberately excluded: they
        occur every time an administrator signs in normally, so alerting on
        them would produce constant noise and teach the operator to ignore
        the rule.
        """
        watched = {
            EVT_GROUP_MEMBER_ADDED: 'was added to a security group',
            EVT_PASSWORD_RESET: 'had its password reset by another account',
        }

        results = []
        for event in events:
            action = watched.get(event.event_type)
            if action is None:
                continue

            results.append(
                RuleResult(
                    rule_id='R-07',
                    event=event,
                    severity=SEVERITY_MEDIUM,
                    alert_type='PRIVILEGE_CHANGE',
                    message=(
                        f"Account '{event.username or 'unknown'}' {action}. "
                        f"Verify the change was authorised."
                    ),
                )
            )
        return results

    # ------------------------------------------------------------------
    # R-08: an account was locked out
    # ------------------------------------------------------------------

    @staticmethod
    def rule_08_lockout(events):
        """
        A lockout is Windows itself concluding that too many failures
        occurred — independent corroboration of a password attack, and
        meaningful even when the failures happened outside R-01's window.
        """
        return [
            RuleResult(
                rule_id='R-08',
                event=event,
                severity=SEVERITY_MEDIUM,
                alert_type='ACCOUNT_LOCKOUT',
                message=(
                    f"Windows locked out account '{event.username or 'unknown'}' "
                    f"after repeated failed sign-ins."
                ),
            )
            for event in events
            if event.event_type == EVT_ACCOUNT_LOCKOUT
        ]

    # ------------------------------------------------------------------
    # R-09: an external storage device was connected
    # ------------------------------------------------------------------

    @staticmethod
    def rule_09_external_device(events):
        """
        A USB drive is the route by which data leaves a machine that is
        otherwise watched only at the network edge, and the route by which
        malware arrives on one that has no network at all.

        Every connection raises an alert, with no threshold: unlike a failed
        password there is no innocent background rate to filter out, and the
        collector has already discarded the internal hardware that Windows
        enumerates at boot. Severity is medium because plugging in a drive is
        ordinary behaviour — the alert asks the administrator to confirm it
        was expected, rather than declaring an attack.
        """
        return [
            RuleResult(
                rule_id='R-09',
                event=event,
                severity=SEVERITY_MEDIUM,
                alert_type='USB_DEVICE_CONNECTED',
                message=(
                    f"External device '{event.device_name or 'unknown device'}' "
                    f"was connected by '{event.username or 'unknown'}'. "
                    f"Confirm the removable media was authorised."
                ),
            )
            for event in events
            if event.event_type == EVT_USB_DEVICE_CONNECTED
        ]

    # ------------------------------------------------------------------
    # R-10: a watched file changed
    # ------------------------------------------------------------------

    @staticmethod
    def rule_10_file_integrity(events):
        """
        A file under integrity monitoring stopped matching its baseline.

        This is the rule that catches what happens *after* a break-in. Every
        other rule here watches the front door; an intruder who is already
        inside persists by editing a startup script, replacing a binary or
        dropping a payload into a directory nobody reads. None of that
        produces an authentication event, so nothing else in this engine would
        ever see it.

        Severity follows how hard the change is to explain innocently. A
        modified or deleted file was already known and trusted, and something
        deliberately changed it, so both are HIGH. A newly appeared file is
        MEDIUM: unexpected, worth looking at, but a directory legitimately
        gains files during ordinary use and treating that as critical would
        train the operator to dismiss the rule.

        There is no threshold. Unlike a failed password there is no innocent
        background rate of watched system files silently changing, and the
        scanner has already established a baseline precisely so that routine
        state is not reported as a finding.
        """
        severities = {
            EVT_FILE_MODIFIED: SEVERITY_HIGH,
            EVT_FILE_DELETED: SEVERITY_HIGH,
            EVT_FILE_ADDED: SEVERITY_MEDIUM,
        }
        wording = {
            EVT_FILE_MODIFIED: 'was modified',
            EVT_FILE_DELETED: 'was deleted',
            EVT_FILE_ADDED: 'appeared',
        }

        return [
            RuleResult(
                rule_id='R-10',
                event=event,
                severity=severities[event.event_type],
                alert_type='FILE_INTEGRITY',
                message=(
                    f"Integrity check failed: '{event.file_path or 'unknown file'}' "
                    f"{wording[event.event_type]} on {event.host.hostname if event.host else 'a monitored host'}. "
                    f"Confirm the change was authorised."
                ),
            )
            for event in events
            if event.event_type in severities
        ]

    # ------------------------------------------------------------------
    # Threat Intelligence registry upkeep
    # ------------------------------------------------------------------

    @staticmethod
    def _refresh_registry(events):
        """
        Record every routable source IP seen in a failure event.

        New addresses are added as UNKNOWN so the administrator can later
        promote them to TRUSTED or BANNED from the Configuration page.
        """
        seen = defaultdict(int)
        last_seen = {}

        for event in events:
            if event.event_type not in FAILURE_EVENT_TYPES:
                continue
            if _is_non_routable(event.source_ip):
                continue
            seen[event.source_ip] += 1
            known = last_seen.get(event.source_ip)
            if known is None or event.timestamp > known:
                last_seen[event.source_ip] = event.timestamp

        if not seen:
            return

        existing = {
            entry.ip_address: entry
            for entry in IPRegistry.query.filter(IPRegistry.ip_address.in_(seen.keys())).all()
        }

        for ip_address, count in seen.items():
            entry = existing.get(ip_address)
            if entry is None:
                entry = IPRegistry(
                    ip_address=ip_address,
                    status=IP_UNKNOWN,
                    source='Auto-registered by detection engine',
                    date_added=utcnow(),
                )
                db.session.add(entry)

            entry.hit_count = count
            entry.last_seen = last_seen[ip_address]

        db.session.commit()

    # ------------------------------------------------------------------
    # Persistence and de-duplication
    # ------------------------------------------------------------------

    @staticmethod
    def _persist(candidates):
        """
        Write candidate alerts to the database, skipping duplicates and events
        from explicitly trusted sources.
        """
        counts = {
            'R-01': 0, 'R-02': 0, 'R-03': 0, 'R-04': 0,
            'R-05': 0, 'R-06': 0, 'R-07': 0, 'R-08': 0,
            'R-09': 0, 'R-10': 0,
        }

        if not candidates:
            counts['total'] = 0
            return counts

        trusted = {
            entry.ip_address
            for entry in IPRegistry.query.filter_by(status=IP_TRUSTED).all()
        }

        # One query for all existing (rule, event) pairs beats one per candidate.
        event_ids = {c.event.id for c in candidates}
        already = {
            (rule_id, event_id)
            for rule_id, event_id in db.session.query(Alert.rule_id, Alert.event_id)
            .filter(Alert.event_id.in_(event_ids))
            .all()
        }

        for candidate in candidates:
            key = (candidate.rule_id, candidate.event.id)
            if key in already:
                continue
            if candidate.event.source_ip in trusted:
                continue

            db.session.add(
                Alert(
                    host_id=candidate.host_id,
                    event_id=candidate.event.id,
                    timestamp=candidate.event.timestamp,
                    rule_id=candidate.rule_id,
                    alert_type=candidate.alert_type,
                    message=candidate.message,
                    severity=candidate.severity,
                    source_ip=candidate.event.source_ip,
                )
            )
            already.add(key)
            counts[candidate.rule_id] += 1

        db.session.commit()
        counts['total'] = sum(
            counts[rule] for rule in counts if rule.startswith('R-')
        )
        return counts


def _is_non_routable(source_ip):
    """True for local/console markers that should never raise a remote-attacker alert."""
    return source_ip in NON_ROUTABLE_MARKERS


def _describe_source(source_ip):
    """
    Name where an attempt came from, in a sentence.

    "from LOCAL_CONSOLE" is an internal marker leaking into prose that a
    supervisor is going to read. The markers describe a place rather than an
    address, so they are worded as one.
    """
    if _is_non_routable(source_ip):
        return 'at the machine\'s own console'
    return f'from {source_ip}'


def _config(key, default):
    """Read a tuning value from Flask config, falling back outside an app context."""
    try:
        return current_app.config.get(key, default)
    except RuntimeError:
        return default
