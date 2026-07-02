import pandas as pd
from pathlib import Path
from datetime import datetime


class DataManager:
    """Handles forensic retention of collected logs as Parquet files."""

    STORAGE_DIR = Path.cwd() / "storage"

    @staticmethod
    def ensure_storage():
        """Create the storage folder if it doesn't already exist."""
        DataManager.STORAGE_DIR.mkdir(exist_ok=True)

    @staticmethod
    def save_logs_to_parquet(log_list, host_id):
        """Save a list of log event dicts to a Parquet file. Returns (filename, record_count)."""
        DataManager.ensure_storage()

        if not log_list:
            return None, 0

        df = pd.DataFrame(log_list)

        expected_cols = ['timestamp', 'source_ip', 'alert_type', 'user', 'message', 'raw_log']
        for col in expected_cols:
            if col not in df.columns:
                df[col] = None

        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"logs_{host_id}_{timestamp_str}.parquet"
        file_path = DataManager.STORAGE_DIR / filename

        try:
            df.to_parquet(file_path, engine='pyarrow', index=False)
            return filename, len(df)
        except Exception as e:
            print(f"Error writing Parquet file: {e}")
            raise e

    @staticmethod
    def load_logs(filename):
        """Load a Parquet file into a DataFrame."""
        DataManager.ensure_storage()
        file_path = DataManager.STORAGE_DIR / filename

        if not file_path.exists():
            print(f"Warning: file {filename} does not exist.")
            return pd.DataFrame()

        try:
            df = pd.read_parquet(file_path, engine='pyarrow')
            return df
        except Exception as e:
            print(f"Error reading Parquet file {filename}: {e}")
            return pd.DataFrame()
