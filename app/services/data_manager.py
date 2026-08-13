"""
Forensic retention of collected logs.

Every batch of events is written to a Parquet file before analysis, so the
raw evidence survives even if the alerts derived from it are later cleared.
Parquet is columnar and compressed, which keeps retained logs small and quick
to filter when replaying an incident.
"""
from datetime import datetime
from pathlib import Path

import pandas as pd
from flask import current_app

# Columns every archived batch carries, so files stay schema-compatible even
# when a particular log source didn't populate all of them.
EXPECTED_COLUMNS = ('timestamp', 'source_ip', 'alert_type', 'user', 'message', 'raw_log')

DEFAULT_STORAGE_DIR = Path.cwd() / 'storage'


class DataManager:

    @staticmethod
    def storage_dir():
        """
        Resolve the storage folder from Flask config.

        Falling back to a path relative to the working directory keeps the
        service usable from standalone scripts that have no app context.
        """
        try:
            configured = current_app.config.get('STORAGE_FOLDER')
        except RuntimeError:
            configured = None

        return Path(configured) if configured else DEFAULT_STORAGE_DIR

    @staticmethod
    def ensure_storage():
        """Create the storage folder if it doesn't already exist."""
        folder = DataManager.storage_dir()
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    @staticmethod
    def save_logs_to_parquet(log_list, host_id):
        """
        Save a list of normalized event dicts to a Parquet file.

        Returns (filename, record_count), or (None, 0) for an empty batch.
        """
        if not log_list:
            return None, 0

        folder = DataManager.ensure_storage()
        df = pd.DataFrame(log_list)

        for column in EXPECTED_COLUMNS:
            if column not in df.columns:
                df[column] = None

        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        filename = f"logs_{host_id}_{timestamp_str}.parquet"

        # Mixed types (datetimes alongside strings) upset the Parquet writer,
        # so anything that isn't the timestamp column is stored as text.
        for column in df.columns:
            if column != 'timestamp':
                df[column] = df[column].astype('string')

        df.to_parquet(folder / filename, engine='pyarrow', index=False)
        return filename, len(df)

    @staticmethod
    def load_logs(filename):
        """Load an archived Parquet file into a DataFrame, or an empty one if missing."""
        if not filename:
            return pd.DataFrame()

        file_path = DataManager.storage_dir() / filename
        if not file_path.exists():
            return pd.DataFrame()

        try:
            return pd.read_parquet(file_path, engine='pyarrow')
        except Exception as exc:
            print(f"Error reading Parquet file {filename}: {exc}")
            return pd.DataFrame()

    @staticmethod
    def list_archives():
        """List retained Parquet files, newest first."""
        folder = DataManager.storage_dir()
        if not folder.exists():
            return []

        files = sorted(
            folder.glob('*.parquet'),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return [{'name': p.name, 'size': p.stat().st_size} for p in files]
