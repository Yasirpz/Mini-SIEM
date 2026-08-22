"""
File Integrity Monitoring (rule R-10).

Windows and Linux both record who signed in. Neither records that a file
quietly changed — and altering a binary, a configuration file, a scheduled
task or a startup script is how an intruder stays on a machine after the
logon that let them in has scrolled out of the log. Authentication monitoring
answers "who got in"; this answers "what did they leave behind".

The mechanism is deliberately old-fashioned and hard to argue with: hash every
watched file, store the hash, and compare on the next scan. A changed hash is
proof that the bytes changed, whatever the timestamps claim — which matters,
because modification times are trivially forged and hashes are not.

    first scan   →  record hashes, raise nothing   (this is the baseline)
    later scans  →  compare, and report the differences

That first-scan rule is the single most important behaviour here. Without it,
switching monitoring on for a directory of four hundred files would produce
four hundred "new file" alerts, and the operator would learn to ignore the
panel on the day it was turned on. A baseline is established silently; only
departures from it are events.

Three collection methods are supported, matching the rest of the project:
LOCAL hashes with `hashlib` in-process, WINRM runs `Get-FileHash` on the
target over PowerShell remoting, and SSH runs `sha256sum`. All three return
the same records, so the comparison logic below never learns which one it is
looking at.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from app.extensions import db
from app.models import (
    COLLECT_LOCAL,
    COLLECT_SSH,
    COLLECT_WINRM,
    EVT_FILE_ADDED,
    EVT_FILE_DELETED,
    EVT_FILE_MODIFIED,
    FIM_MAX_FILES_PER_PATH,
    FileBaseline,
    WatchedPath,
    utcnow,
)
from app.services.log_analyzer import LogAnalyzer
from app.services.win_client import PowerShellError

log = logging.getLogger(__name__)

# A file bigger than this is recorded by size and modification time only, and
# its hash is left as the marker below. Reading a four-gigabyte file across a
# WinRM channel to hash it would stall the scan for minutes and tell the
# operator nothing they could not learn from the size changing.
MAX_HASHABLE_BYTES = 64 * 1024 * 1024

TOO_LARGE = 'TOO_LARGE'


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_host(host):
    """
    Scan every watched path on a host and report what changed.

    Returns `(payload, status)` in the same shape as `collect_host`, so the
    route, the scheduler and the tests can all treat the two the same way.
    Findings become ordinary Event rows through `LogAnalyzer.ingest`, which
    means they are archived to Parquet, de-duplicated and passed to the
    detection engine exactly like a collected log line. Nothing about this
    feature needs its own pipeline.
    """
    watched = WatchedPath.query.filter_by(host_id=host.id).all()
    if not watched:
        return {
            'message': 'No paths are being watched on this host.',
            'watched_paths': 0,
            'files_checked': 0,
            'changes': [],
        }, 200

    method = host.effective_collection_method()

    try:
        scanned, truncated = _scan_paths(host, watched, method)
    except PowerShellError as exc:
        return _fail(host, 502, f'File integrity scan of {host.ip_address} failed.', str(exc))
    except Exception as exc:
        return _fail(host, 500, 'File integrity scan failed.', str(exc))

    findings, baseline_established = _compare_with_baseline(host, watched, scanned)

    host.last_integrity_scan = utcnow()
    host.last_integrity_error = None
    db.session.commit()

    files_checked = sum(len(records) for records in scanned.values())

    if baseline_established:
        # Say plainly that nothing was checked yet. An operator who sees
        # "0 changes" on the very first scan could reasonably believe the
        # files had been verified against something.
        return {
            'message': (
                f'Baseline recorded for {files_checked} file(s). '
                'Changes will be reported from the next scan onwards.'
            ),
            'baseline_established': True,
            'watched_paths': len(watched),
            'files_checked': files_checked,
            'changes': [],
            'truncated': truncated,
        }, 200

    result = {}
    if findings:
        result = LogAnalyzer.ingest(findings, host.id, origin='COLLECTED')

    return {
        'message': (
            f'{len(findings)} change(s) detected across {files_checked} watched file(s).'
            if findings else
            f'No changes. {files_checked} watched file(s) match their baseline.'
        ),
        'baseline_established': False,
        'watched_paths': len(watched),
        'files_checked': files_checked,
        'changes': [
            {
                'event_type': f['alert_type'],
                'path': f['file_path'],
                'message': f['message'],
            }
            for f in findings
        ],
        'truncated': truncated,
        'alerts': result.get('alerts', {'total': 0}),
        'events_stored': result.get('events_stored', 0),
    }, 200


def _fail(host, status, message, detail):
    """Record a scan failure against the host, then return the payload."""
    host.last_integrity_error = detail[:500]
    db.session.commit()
    log.warning('Integrity scan failed for %s: %s', host.hostname, detail)
    return {'error': message, 'detail': detail}, status


# ---------------------------------------------------------------------------
# Gathering hashes
# ---------------------------------------------------------------------------

def _scan_paths(host, watched, method):
    """
    Hash every file under every watched path.

    Returns `({watched_path_id: [record, ...]}, truncated_paths)` where each
    record is `{path, sha256, size_bytes, modified_at}`. `truncated_paths`
    names the watched paths that hit the file cap, so the caller can say so
    rather than quietly reporting a partial scan as a complete one.
    """
    scanned = {}
    truncated = []

    for entry in watched:
        if method == COLLECT_LOCAL:
            records, hit_cap = _scan_local(entry)
        elif method == COLLECT_WINRM:
            records, hit_cap = _scan_windows_remote(host, entry)
        elif method == COLLECT_SSH:
            records, hit_cap = _scan_linux(host, entry)
        else:
            raise ValueError(f'Unsupported collection method: {method}')

        scanned[entry.id] = records
        if hit_cap:
            truncated.append(entry.path)

    return scanned, truncated


def _scan_local(entry):
    """Hash files on the machine running Mini-SIEM, in-process."""
    root = Path(entry.path)
    records = []

    if not root.exists():
        return records, False

    if root.is_file():
        record = _hash_local_file(root)
        return ([record] if record else []), False

    walker = root.rglob('*') if entry.recursive else root.glob('*')

    hit_cap = False
    for candidate in walker:
        if len(records) >= FIM_MAX_FILES_PER_PATH:
            hit_cap = True
            break
        if not candidate.is_file():
            continue
        record = _hash_local_file(candidate)
        if record:
            records.append(record)

    return records, hit_cap


def _hash_local_file(path):
    """
    One file's hash, size and modification time, or None if it cannot be read.

    An unreadable file is skipped rather than raised: a locked or
    permission-denied file in a watched directory must not abort the scan of
    everything else in it.
    """
    try:
        stat = path.stat()
        if stat.st_size > MAX_HASHABLE_BYTES:
            digest = TOO_LARGE
        else:
            digest = hashlib.sha256()
            with path.open('rb') as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                    digest.update(chunk)
            digest = digest.hexdigest()

        return {
            'path': str(path),
            'sha256': digest,
            'size_bytes': stat.st_size,
            # st_mtime is epoch seconds; reading it through the local
            # clock would store a different time than utcnow() does.
            'modified_at': datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).replace(tzinfo=None),
        }
    except (OSError, ValueError) as exc:
        log.debug('Skipping unreadable file %s: %s', path, exc)
        return None


def _scan_windows_remote(host, entry):
    """
    Hash files on a remote Windows host with Get-FileHash.

    Emits one JSON object per line for the same reason the Security log query
    does: ConvertTo-Json renders a lone object differently from several, and a
    directory that happens to hold exactly one file must not parse differently
    from every other directory.
    """
    from app.services.collection import _winrm_for

    win = _winrm_for(host)
    script = _windows_hash_script(entry)
    return _parse_hash_records(win.run_ps(script))


def _windows_hash_script(entry):
    """The PowerShell that hashes one watched path on a Windows host."""
    quoted = entry.path.replace("'", "''")
    recurse = ' -Recurse' if entry.recursive else ''

    return (
        "$ErrorActionPreference='Stop'; "
        f"$target = '{quoted}'; "
        "if (-not (Test-Path -LiteralPath $target)) { exit 0 } "
        "$items = @(); "
        "if (Test-Path -LiteralPath $target -PathType Leaf) { "
        "   $items = @(Get-Item -LiteralPath $target) "
        "} else { "
        f"   $items = @(Get-ChildItem -LiteralPath $target{recurse} -File "
        f"      -ErrorAction SilentlyContinue | Select-Object -First {FIM_MAX_FILES_PER_PATH + 1}) "
        "} "
        "foreach ($item in $items) { "
        # A file that cannot be read is skipped, never fatal: one locked file
        # must not cost the operator the scan of the whole directory.
        "   try { "
        f"      if ($item.Length -gt {MAX_HASHABLE_BYTES}) {{ "
        f"         $hash = '{TOO_LARGE}' "
        "      } else { "
        "         $hash = (Get-FileHash -LiteralPath $item.FullName "
        "                  -Algorithm SHA256 -ErrorAction Stop).Hash "
        "      } "
        "      [PSCustomObject]@{ "
        "         Path = $item.FullName; "
        "         Sha256 = $hash; "
        "         Size = $item.Length; "
        "         Modified = $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); "
        "      } | ConvertTo-Json -Compress "
        "   } catch { continue } "
        "}"
    )


def _scan_linux(host, entry):
    """Hash files on a remote Linux host with find + sha256sum."""
    from app.services.collection import _ssh_for

    quoted = "'" + entry.path.replace("'", "'\\''") + "'"
    depth = '' if entry.recursive else ' -maxdepth 1'
    limit = FIM_MAX_FILES_PER_PATH + 1

    # stat and sha256sum are run per file and joined with a separator rather
    # than parsed from two commands, so a filename containing spaces cannot
    # shift the columns apart.
    command = (
        f'find {quoted}{depth} -type f 2>/dev/null | head -n {limit} | '
        'while IFS= read -r f; do '
        '  h=$(sha256sum -- "$f" 2>/dev/null | cut -d" " -f1); '
        '  s=$(stat -c %s -- "$f" 2>/dev/null); '
        '  m=$(stat -c %y -- "$f" 2>/dev/null | cut -d. -f1); '
        '  [ -n "$h" ] && printf \'%s\\t%s\\t%s\\t%s\\n\' "$h" "$s" "$m" "$f"; '
        'done'
    )

    with _ssh_for(host) as remote:
        stdout, _ = remote.run(command)

    records = []
    for line in (stdout or '').splitlines():
        parts = line.split('\t')
        if len(parts) != 4:
            continue
        digest, size, modified, path = parts
        records.append({
            'path': path,
            'sha256': digest,
            'size_bytes': _int_or_none(size),
            'modified_at': _parse_timestamp(modified),
        })

    hit_cap = len(records) > FIM_MAX_FILES_PER_PATH
    return records[:FIM_MAX_FILES_PER_PATH], hit_cap


def _parse_hash_records(stdout):
    """Turn NDJSON hash output into records, ignoring anything unparseable."""
    records = []
    for line in (stdout or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue

        path = (row.get('Path') or '').strip()
        digest = (row.get('Sha256') or '').strip()
        if not path or not digest:
            continue

        records.append({
            'path': path,
            'sha256': digest,
            'size_bytes': _int_or_none(row.get('Size')),
            'modified_at': _parse_timestamp(row.get('Modified')),
        })

    hit_cap = len(records) > FIM_MAX_FILES_PER_PATH
    return records[:FIM_MAX_FILES_PER_PATH], hit_cap


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def _compare_with_baseline(host, watched, scanned):
    """
    Compare a scan against the stored baseline and update it.

    Returns `(findings, baseline_established)`. `baseline_established` is True
    on the first scan of a host, when the baseline is written and deliberately
    nothing is reported — see the note at the top of this module.
    """
    baselines = {
        row.path: row
        for row in FileBaseline.query.filter_by(host_id=host.id).all()
    }
    first_scan = not baselines

    watched_ids = {entry.id for entry in watched}
    findings = []
    seen_paths = set()
    now = utcnow()

    for watched_id, records in scanned.items():
        for record in records:
            path = record['path']
            seen_paths.add(path)
            existing = baselines.get(path)

            if existing is None:
                db.session.add(FileBaseline(
                    host_id=host.id,
                    watched_path_id=watched_id,
                    path=path,
                    sha256=record['sha256'],
                    size_bytes=record['size_bytes'],
                    modified_at=record['modified_at'],
                    first_seen=now,
                    last_seen=now,
                ))
                if not first_scan:
                    findings.append(_finding(
                        EVT_FILE_ADDED, path, now,
                        f"New file appeared in a watched location: {path}",
                        record,
                    ))
                continue

            existing.last_seen = now
            existing.watched_path_id = watched_id

            if existing.sha256 != record['sha256']:
                findings.append(_finding(
                    EVT_FILE_MODIFIED, path, now,
                    (
                        f"Watched file was modified: {path} "
                        f"(SHA-256 {_short(existing.sha256)} -> {_short(record['sha256'])})"
                    ),
                    record,
                    previous=existing,
                ))
                existing.sha256 = record['sha256']
                existing.last_changed = now

            existing.size_bytes = record['size_bytes']
            existing.modified_at = record['modified_at']

    # Anything the baseline knows about that this scan did not find, but only
    # under a path that was actually scanned. Without that restriction,
    # removing a watched path would report every file under it as deleted.
    for path, row in baselines.items():
        if path in seen_paths or row.watched_path_id not in watched_ids:
            continue
        findings.append(_finding(
            EVT_FILE_DELETED, path, now,
            f"Watched file is missing: {path}",
            {'sha256': row.sha256, 'size_bytes': row.size_bytes},
        ))
        db.session.delete(row)

    db.session.commit()
    return findings, first_scan


def _finding(event_type, path, when, message, record, previous=None):
    """
    Build a normalized event dict for the ingestion pipeline.

    `source_ip` is LOCAL_CONSOLE for the same reason a USB event is: a file
    changing has no remote address, and the detection engine already treats
    that marker as non-routable, so an integrity finding can never be mistaken
    for a brute-force attempt or promoted into the threat-IP registry.
    """
    raw = {
        'path': path,
        'sha256': record.get('sha256'),
        'size_bytes': record.get('size_bytes'),
    }
    if previous is not None:
        raw['previous_sha256'] = previous.sha256
        raw['previous_size_bytes'] = previous.size_bytes

    return {
        'timestamp': when,
        'alert_type': event_type,
        'source_ip': 'LOCAL_CONSOLE',
        # No user: hashing a file tells you it changed, never who changed it.
        # Claiming otherwise would be inventing evidence.
        'user': 'UNKNOWN',
        'message': message,
        'file_path': path,
        'raw_log': json.dumps(raw, default=str),
    }


def _short(digest):
    """First twelve characters of a hash — enough to compare by eye."""
    return (digest or '')[:12]


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).strip())
    except ValueError:
        return None
