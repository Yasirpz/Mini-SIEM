"""
ATT&CK coverage: rules described in a vocabulary outside this project.

Every alert carries a rule id, and a rule id is only meaningful to someone who
has read the source. Tagging each rule with its MITRE ATT&CK technique turns
"R-05 fired" into "someone cleared the Windows event log, which is T1070.001,
a Defense Evasion technique" -- a statement an evaluator can verify against a
public catalogue.

The tests here guard the two ways that can go wrong. The first is a rule that
exists in the engine and not in the catalogue, which is exactly the failure
that once hid every file-integrity alert from the rules chart. The second is a
coverage panel that flatters the system: a technique that has never fired must
still be listed, as watched-but-not-seen, because a panel that only showed
what had triggered would be advertising rather than reporting.
"""
from app import rule_catalog
from app.models import Alert, utcnow
from app.extensions import db


def raise_alert(host_id, rule_id, severity='HIGH'):
    """Store one alert directly, so a rule can be exercised in isolation."""
    alert = Alert(
        host_id=host_id,
        rule_id=rule_id,
        alert_type='TEST',
        message=f'Synthetic alert for {rule_id}',
        severity=severity,
        source_ip='198.51.100.10',
        timestamp=utcnow(),
    )
    db.session.add(alert)
    db.session.commit()
    return alert


# ---------------------------------------------------------------------------
# The catalogue itself
# ---------------------------------------------------------------------------

def test_every_rule_has_a_technique_and_a_tactic():
    for rule_id, rule in rule_catalog.RULES.items():
        assert rule.technique_id.startswith('T'), rule_id
        assert rule.technique_name, rule_id
        assert rule.tactic in rule_catalog.TACTIC_ORDER, (
            f'{rule_id} is tagged with a tactic that is not an ATT&CK tactic: '
            f'{rule.tactic}'
        )
        # A mapping with no reasoning behind it is a label, not a decision.
        assert len(rule.rationale) > 40, rule_id


def test_a_sub_technique_resolves_to_its_own_attack_page():
    """attack.mitre.org nests sub-techniques under the parent, not beside it."""
    assert rule_catalog.RULES['R-05'].technique_url == (
        'https://attack.mitre.org/techniques/T1070/001/'
    )
    assert rule_catalog.RULES['R-02'].technique_url == (
        'https://attack.mitre.org/techniques/T1110/'
    )


def test_tactics_are_listed_in_kill_chain_order():
    """
    The order is what makes a gap visible: an evaluator reading left to right
    sees which stage of an intrusion is unobserved.
    """
    tactics = rule_catalog.tactics_in_order()

    assert tactics == sorted(
        tactics, key=rule_catalog.TACTIC_ORDER.index
    )
    # Only tactics some rule actually covers. Claiming an empty column would
    # overstate what the system can see.
    assert set(tactics) == {rule.tactic for rule in rule_catalog.RULES.values()}


# ---------------------------------------------------------------------------
# The alert payload
# ---------------------------------------------------------------------------

def test_an_alert_carries_its_technique(app, host):
    alert = raise_alert(host.id, 'R-07')

    data = alert.to_dict()

    assert data['rule_name'] == 'Privilege Change'
    assert data['technique_id'] == 'T1098'
    assert data['technique_name'] == 'Account Manipulation'
    assert data['tactic'] == 'Persistence'
    assert data['technique_url'].endswith('/T1098/')


def test_an_alert_with_an_unknown_rule_still_serialises(app, host):
    """
    A row left by an older version, or a hand-edited database, must not take
    the alerts page down with it.
    """
    alert = raise_alert(host.id, 'R-99')

    data = alert.to_dict()

    assert data['rule_id'] == 'R-99'
    assert data['technique_id'] is None
    assert data['rule_name'] is None


# ---------------------------------------------------------------------------
# The coverage endpoint
# ---------------------------------------------------------------------------

def test_coverage_lists_every_rule_including_ones_that_never_fired(auth_client):
    data = auth_client.get('/api/stats/attack').get_json()

    assert len(data['techniques']) == len(rule_catalog.RULE_IDS)
    assert data['rules_triggered'] == 0
    assert data['techniques_observed'] == 0
    assert all(entry['alerts'] == 0 for entry in data['techniques'])
    assert all(entry['last_seen'] is None for entry in data['techniques'])


def test_coverage_counts_alerts_against_the_right_technique(auth_client, host):
    raise_alert(host.id, 'R-05')
    raise_alert(host.id, 'R-05')
    raise_alert(host.id, 'R-10')

    data = auth_client.get('/api/stats/attack').get_json()
    by_rule = {entry['rule_id']: entry for entry in data['techniques']}

    assert by_rule['R-05']['alerts'] == 2
    assert by_rule['R-05']['technique_id'] == 'T1070.001'
    assert by_rule['R-10']['alerts'] == 1
    assert by_rule['R-01']['alerts'] == 0

    assert data['rules_triggered'] == 2
    assert by_rule['R-05']['last_seen'] is not None


def test_two_rules_sharing_a_technique_are_counted_once(auth_client, host):
    """
    R-02 and R-08 both map to T1110. Counting rules instead of techniques
    would report two techniques observed where only one behaviour was seen.
    """
    raise_alert(host.id, 'R-02')
    raise_alert(host.id, 'R-08')

    data = auth_client.get('/api/stats/attack').get_json()

    assert data['rules_triggered'] == 2
    assert data['techniques_observed'] == 1
    assert data['techniques_total'] < data['rules_total']


def test_tactics_roll_up_their_rules(auth_client, host):
    raise_alert(host.id, 'R-01')
    raise_alert(host.id, 'R-04')

    data = auth_client.get('/api/stats/attack').get_json()
    by_tactic = {entry['tactic']: entry for entry in data['tactics']}

    # R-01, R-02, R-04 and R-08 are all Credential Access rules; two of them
    # fired, so the tactic carries two alerts and four rules.
    assert by_tactic['Credential Access']['alerts'] == 2
    assert sorted(by_tactic['Credential Access']['rules']) == [
        'R-01', 'R-02', 'R-04', 'R-08',
    ]
    # Impact is covered by file integrity alone and has seen nothing, but is
    # still reported -- that is the difference between "not watched" and
    # "watched, quiet".
    assert by_tactic['Impact']['alerts'] == 0
    assert by_tactic['Impact']['rules'] == ['R-10']


def test_coverage_requires_a_session(client):
    response = client.get('/api/stats/attack')

    assert response.status_code == 401
    assert response.get_json()['error'] == 'Authentication required'
