"""Durable, atomic consumption of verified execution receipts."""

from contextlib import closing
import os
from pathlib import Path
import sqlite3
from typing import Optional, Union


class ReplayStoreError(Exception):
    """Replay state could not be read or durably updated."""


class ReceiptReplayStore:
    """Share one SQLite file between all boundaries for an execution domain.

    Consumption is never refunded: a crash after commit may prevent execution,
    but cannot authorize a second attempt. The file must be retained and stored
    on a filesystem supporting SQLite locking and durable commits.
    """

    def __init__(self, path: Optional[Union[str, Path]] = None):
        """Pin one durable replay path, consulting home only when no override is configured."""
        if path is None:
            path = os.environ.get("GOVERNED_AGENT_REPLAY_STORE_PATH")
            if not path:
                try:
                    path = Path.home() / ".governed_agent" / "receipt_replay.sqlite3"
                except (RuntimeError, KeyError) as exc:
                    raise ReplayStoreError("Replay storage path unavailable") from exc
        configured = Path(path)
        # Capture the execution domain once; tool-induced cwd changes must not
        # redirect later consumption into a fresh database. Keep SQLite's
        # in-memory sentinel intact so consume still rejects ephemeral storage.
        self.path = configured if str(configured) == ":memory:" else configured.resolve()

    def consume(self, issuer_fingerprint: str, receipt_digest: str) -> bool:
        """Commit first consumption, returning False if already consumed.

        A fresh connection per attempt allows threads and processes to share
        SQLite's unique-key and transaction guarantees without an in-memory cache.
        """
        try:
            if str(self.path) == ":memory:":
                raise ReplayStoreError("Replay storage must be durable")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(str(self.path), timeout=5.0)) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS consumed_receipts ("
                        "issuer_fingerprint TEXT NOT NULL, "
                        "receipt_digest TEXT NOT NULL, "
                        "PRIMARY KEY (issuer_fingerprint, receipt_digest))"
                    )
                    cursor = connection.execute(
                        "INSERT INTO consumed_receipts (issuer_fingerprint, receipt_digest) "
                        "VALUES (?, ?) ON CONFLICT (issuer_fingerprint, receipt_digest) DO NOTHING",
                        (issuer_fingerprint, receipt_digest),
                    )
                    consumed = cursor.rowcount == 1
                # Leaving the transaction commits before returning to the caller.
                return consumed
        except (OSError, sqlite3.Error) as exc:
            raise ReplayStoreError("Replay state is unavailable") from exc
