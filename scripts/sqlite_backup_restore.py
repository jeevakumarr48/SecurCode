"""Create verified SQLite backups and isolated restore copies without overwriting."""

import argparse
from pathlib import Path
import sqlite3


def _read_only_connection(path):
    source_path = Path(path)
    if not source_path.is_file():
        raise FileNotFoundError("Source database does not exist.")
    return sqlite3.connect(
        source_path.resolve().as_uri() + "?mode=ro",
        uri=True,
        timeout=10,
    )


def _verify_database(connection, description):
    integrity = connection.execute("PRAGMA integrity_check").fetchone()
    if integrity is None or integrity[0] != "ok":
        raise RuntimeError(f"{description} failed SQLite integrity_check.")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise RuntimeError(f"{description} failed SQLite foreign_key_check.")


def _copy_to_new_database(source_path, destination_path, description):
    destination_path = Path(destination_path)
    if not destination_path.parent.is_dir():
        raise FileNotFoundError("Destination directory does not exist.")
    if Path(source_path).resolve() == destination_path.resolve():
        raise ValueError("Source and destination must be different paths.")

    source = _read_only_connection(source_path)
    try:
        _verify_database(source, "Source database")
        destination_created = False
        verified = False
        try:
            with destination_path.open("xb"):
                pass
            destination_created = True
            destination = sqlite3.connect(destination_path, timeout=10)
            try:
                source.backup(destination)
                _verify_database(destination, description)
            finally:
                destination.close()
            verified = True
        finally:
            if destination_created and not verified:
                destination_path.unlink(missing_ok=True)
    finally:
        source.close()


def backup_database(source_path, backup_path):
    """Create a consistent online backup at a destination that must not exist."""
    _copy_to_new_database(source_path, backup_path, "Backup")


def restore_database(backup_path, restored_path):
    """Restore a verified backup to a new path; never switches or replaces a database."""
    _copy_to_new_database(backup_path, restored_path, "Restored database")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("backup", "restore"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()

    if args.operation == "backup":
        backup_database(args.source, args.destination)
    else:
        restore_database(args.source, args.destination)
    print(f"{args.operation.capitalize()} verified with SQLite integrity and foreign-key checks.")


if __name__ == "__main__":
    main()
