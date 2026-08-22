"""
What each detection rule is, and which adversary behaviour it corresponds to.

Until now the rule identifiers R-01..R-10 were the only thing an alert carried
about *why* it fired, and their human-readable names lived in the stats API,
where nothing else could reach them. That had two costs. The obvious one was a
bug: R-10 was added to the engine and never added to the name table, so
file-integrity alerts were written to the database and then silently left out
of the "Alerts by Detection Rule" chart. The subtler one is that "R-07" means
nothing to anybody who has not read the source, which makes an alert hard to
act on and impossible to compare with anything outside this project.

Both are fixed by naming the rules once, here, and by saying what each rule
detects in the vocabulary the rest of the industry already uses: MITRE ATT&CK.
ATT&CK is the public catalogue of things attackers actually do, organised into
tactics (the attacker's goal) and techniques (how they pursue it). Tagging a
rule with its technique turns a private rule number into a statement a reader
can look up -- "R-05 fired" becomes "someone cleared the Windows event log,
which is ATT&CK T1070.001, a Defense Evasion technique" -- and it lets the
dashboard answer a question a list of alerts cannot: which *stages* of an
intrusion this deployment can actually see, and which it is blind to.

This module is deliberately dependency-free reference data. Nothing here
queries the database or imports the application, so the models, the API and
the documentation build can all read from it without an import cycle.

Mappings are to ATT&CK Enterprise. Where a rule could reasonably be tagged
with more than one technique the closest single one is used and the others are
named in `rationale`, because a rule that claims four techniques makes the
coverage picture look better than it really is.
"""

# ATT&CK tactics, in the order an intrusion tends to move through them. The
# dashboard reads this order so the coverage panel lays out as a kill chain
# rather than alphabetically, which is what makes a gap visible.
TACTIC_ORDER = (
    'Reconnaissance',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Exfiltration',
    'Impact',
)


class RuleInfo:
    """Reference data for one detection rule."""

    def __init__(self, rule_id, name, summary, technique_id, technique_name,
                 tactic, rationale):
        self.rule_id = rule_id
        self.name = name
        self.summary = summary
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.tactic = tactic
        self.rationale = rationale

    @property
    def technique_url(self):
        """
        The public ATT&CK page for this technique.

        Built from the identifier rather than stored, so a sub-technique such
        as T1070.001 resolves to its parent page plus the sub-technique path,
        which is how attack.mitre.org is laid out.
        """
        parts = self.technique_id.split('.')
        return 'https://attack.mitre.org/techniques/{}/'.format('/'.join(parts))

    def to_dict(self):
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'summary': self.summary,
            'technique_id': self.technique_id,
            'technique_name': self.technique_name,
            'technique_url': self.technique_url,
            'tactic': self.tactic,
            'rationale': self.rationale,
        }


RULES = {
    rule.rule_id: rule
    for rule in (
        RuleInfo(
            'R-01', 'Failed Login',
            'Repeated authentication failures for one user from one source '
            'address inside a short window.',
            'T1110.001', 'Brute Force: Password Guessing', 'Credential Access',
            'The account exists and its password is being guessed at, which '
            'is password guessing rather than spraying: one account, many '
            'attempts.',
        ),
        RuleInfo(
            'R-02', 'Invalid User',
            'Authentication attempted against an account that does not exist '
            'on the host.',
            'T1110', 'Brute Force', 'Credential Access',
            'Trying usernames that are not there is also how an attacker '
            'learns which ones are, so this overlaps account discovery '
            '(T1087). It is tagged as brute force because what was actually '
            'observed is an authentication attempt, not a directory query.',
        ),
        RuleInfo(
            'R-03', 'Threat IP Match',
            'Activity from a source address already marked BANNED in the '
            'threat intelligence registry.',
            'T1133', 'External Remote Services', 'Initial Access',
            'A known-bad address reaching an authentication service is an '
            'attempt to get in through the front door. The rule says nothing '
            'about what that address then did -- only that it should not have '
            'been talking to a monitored host at all.',
        ),
        RuleInfo(
            'R-04', 'Multiple Host Attempt',
            'One source address attempting authentication against several '
            'monitored hosts.',
            'T1110.003', 'Brute Force: Password Spraying', 'Credential Access',
            'Breadth rather than depth -- a few attempts across many machines '
            'is the shape of spraying, and it is also the shape of an '
            'attacker mapping which hosts answer at all.',
        ),
        RuleInfo(
            'R-05', 'Audit Log Cleared',
            'The Windows Security event log was cleared on a monitored host.',
            'T1070.001', 'Indicator Removal: Clear Windows Event Logs',
            'Defense Evasion',
            'Clearing the log is not a side effect of anything legitimate on '
            'a monitored machine; it is done to remove the record of what '
            'came before it, which is why a single event is enough to raise a '
            'high-severity alert.',
        ),
        RuleInfo(
            'R-06', 'Account Created or Deleted',
            'A local account was created, enabled or deleted on a monitored '
            'host.',
            'T1136.001', 'Create Account: Local Account', 'Persistence',
            'A new local account is a way back in that survives the password '
            'change following an incident. Deletion is grouped with it '
            'because it is the same rule read backwards: removing the account '
            'that was used.',
        ),
        RuleInfo(
            'R-07', 'Privilege Change',
            'A password was reset by another user, or an account was added to '
            'a privileged group.',
            'T1098', 'Account Manipulation', 'Persistence',
            'Modifying an account that already exists keeps the attacker '
            'inside an identity the system already trusts, which is quieter '
            'than creating a new one -- and is why this is a separate rule '
            'from R-06 rather than a variant of it.',
        ),
        RuleInfo(
            'R-08', 'Account Lockout',
            'An account was locked out by the operating system after repeated '
            'failures.',
            'T1110', 'Brute Force', 'Credential Access',
            'The lockout is the consequence of the failures R-01 counts, '
            'which is why it is deliberately excluded from that count. It is '
            'also the one signal that survives when the failures themselves '
            'happened before collection started.',
        ),
        RuleInfo(
            'R-09', 'External Device Connected',
            'A removable storage device was connected to a monitored host.',
            'T1091', 'Replication Through Removable Media', 'Lateral Movement',
            'A USB drive is how malware crosses an air gap and how data '
            'leaves one (T1052.001, Exfiltration over Physical Medium). The '
            'connection alone does not say which, so the alert reports the '
            'device and leaves that judgement to the analyst.',
        ),
        RuleInfo(
            'R-10', 'File Integrity Change',
            'A watched file stopped matching its recorded SHA-256 baseline, '
            'or appeared or disappeared under a watched path.',
            'T1565.001', 'Data Manipulation: Stored Data Manipulation', 'Impact',
            'Nothing in an event log records that a file quietly changed, so '
            'this is the only rule whose evidence the operating system does '
            'not supply. A modified binary or startup script is also how an '
            'intruder persists (T1554), which is why the alert names the file '
            'and not only the host.',
        ),
    )
}

# Backwards-compatible short names, kept because the stats API and the
# documentation both refer to rules by name. Derived rather than duplicated so
# a rule can never again exist in the engine but not in the name table.
RULE_NAMES = {rule_id: rule.name for rule_id, rule in RULES.items()}

# Every rule id the engine can emit, in order. Used wherever a chart or a
# report has to show rules that have not fired alongside those that have -- a
# rule with no alerts is information, not something to omit.
RULE_IDS = tuple(sorted(RULES))


def get(rule_id):
    """Reference data for one rule id, or None if it is not a known rule."""
    return RULES.get(rule_id)


def tactics_in_order():
    """
    The tactics this project's rules cover, in kill-chain order.

    Tactics no rule maps to are left out: claiming a column the system cannot
    fill would misrepresent coverage, which is the opposite of the point.
    """
    covered = {rule.tactic for rule in RULES.values()}
    return [tactic for tactic in TACTIC_ORDER if tactic in covered]
