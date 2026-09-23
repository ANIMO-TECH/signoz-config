"""Bounded durable outbox. Cursor and normalized event commit in one transaction."""

import json
import os
import sqlite3
import uuid
from datetime import timedelta
from pathlib import Path

RETENTION = timedelta(days=30)


class Backpressure(Exception):
    pass


class Journal:
    def __init__(self, path, max_bytes=64 * 1024 * 1024):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink():
            raise ValueError("journal symlink refused")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        self.db = sqlite3.connect(path)
        self.max_bytes = max_bytes
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_size_limit=4194304")
        self.db.execute(
            "PRAGMA max_page_count=" + str(max(256, (max_bytes * 3) // 4096))
        )
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS cursor (source TEXT PRIMARY KEY, offset INTEGER NOT NULL, seen REAL NOT NULL, discarding INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS event (id TEXT PRIMARY KEY, received REAL NOT NULL, payload TEXT NOT NULL, batch TEXT);
          CREATE INDEX IF NOT EXISTS event_batch ON event(batch,received);
          CREATE TABLE IF NOT EXISTS batch (id TEXT PRIMARY KEY, created REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS counters (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
          INSERT OR IGNORE INTO counters VALUES ('bytes',0);
        """)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    def offset(self, source):
        row = self.db.execute(
            "SELECT offset FROM cursor WHERE source=?", (source,)
        ).fetchone()
        return row[0] if row else 0

    def discarding(self, source):
        row = self.db.execute(
            "SELECT discarding FROM cursor WHERE source=?", (source,)
        ).fetchone()
        return bool(row and row[0])

    def accept(self, source, offset, event, now, discarding=False):
        value = dict(event, event_id=uuid.uuid4().hex) if event else None
        payload = (
            json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            if value
            else None
        )
        size = len(payload.encode()) if payload else 0
        with self.db:
            used = self.db.execute(
                "SELECT value FROM counters WHERE key='bytes'"
            ).fetchone()[0]
            if used + size > self.max_bytes:
                raise Backpressure("spool capacity reached")
            if payload:
                self.db.execute(
                    "INSERT INTO event VALUES (?,?,?,NULL)",
                    (value["event_id"], now.timestamp(), payload),
                )
                self.db.execute(
                    "UPDATE counters SET value=value+? WHERE key='bytes'", (size,)
                )
            self.db.execute(
                "INSERT INTO cursor VALUES (?,?,?,?) ON CONFLICT(source) DO UPDATE SET offset=excluded.offset,seen=excluded.seen,discarding=excluded.discarding",
                (source, offset, now.timestamp(), int(discarding)),
            )

    def prepare(self, now, limit=500):
        with self.db:
            row = self.db.execute(
                "SELECT id,created FROM batch WHERE created<=? ORDER BY created LIMIT 1",
                (now.timestamp(),),
            ).fetchone()
            if row:
                return dict(id=row[0], created=row[1])
            first = self.db.execute(
                "SELECT MIN(received) FROM event WHERE batch IS NULL AND received<=?",
                (now.timestamp(),),
            ).fetchone()[0]
            if first is None:
                return None
            # Preserve the original receipt clock during a prolonged upload outage.
            # Each immutable batch spans at most one UTC minute.
            end = (int(first) // 60 + 1) * 60
            rows = list(
                self.db.execute(
                    "SELECT id,received FROM event WHERE batch IS NULL AND received<? AND received<=? ORDER BY received,id LIMIT ?",
                    (end, now.timestamp(), limit),
                )
            )
            ids = [x[0] for x in rows]
            origin = max(x[1] for x in rows)
            ident = uuid.uuid4().hex
            self.db.execute("INSERT INTO batch VALUES (?,?)", (ident, origin))
            self.db.executemany(
                "UPDATE event SET batch=? WHERE id=?", [(ident, x) for x in ids]
            )
            return dict(id=ident, created=origin)

    def future_count(self, now):
        return self.db.execute(
            "SELECT count(*) FROM event WHERE received>?", (now.timestamp(),)
        ).fetchone()[0]

    def batch_events(self, ident):
        return [
            json.loads(x[0])
            for x in self.db.execute(
                "SELECT payload FROM event WHERE batch=? ORDER BY received,id", (ident,)
            )
        ]

    def ack(self, ident):
        with self.db:
            # SQLite length(TEXT) counts characters, not UTF-8 bytes.
            size = self.db.execute(
                "SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM event WHERE batch=?",
                (ident,),
            ).fetchone()[0]
            self.db.execute("DELETE FROM event WHERE batch=?", (ident,))
            self.db.execute("DELETE FROM batch WHERE id=?", (ident,))
            self.db.execute(
                "UPDATE counters SET value=value-? WHERE key='bytes'", (size,)
            )
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def expire(self, now, cursor_inventory=None):
        cutoff = (now - RETENTION).timestamp()
        with self.db:
            # A sealed batch must remain byte-for-byte identical across upload retries.
            predicate = "(batch IS NULL AND received<=?) OR batch IN (SELECT id FROM batch WHERE created<=?)"
            count, size = self.db.execute(
                "SELECT count(*),COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM event WHERE "
                + predicate,
                (cutoff, cutoff),
            ).fetchone()
            self.db.execute("DELETE FROM event WHERE " + predicate, (cutoff, cutoff))
            self.db.execute(
                "DELETE FROM batch WHERE id NOT IN (SELECT batch FROM event WHERE batch IS NOT NULL)"
            )
            self.db.execute(
                "UPDATE counters SET value=value-? WHERE key='bytes'", (size,)
            )
            # An old cursor can still point at a retained source file. Forgetting it
            # after a long shutdown replays acknowledged events with a new receipt
            # time. Prune only against a current source inventory, never age alone.
            if cursor_inventory is not None:
                live_files, uncertain_sources = cursor_inventory
                marker = ""
                while True:
                    rows = self.db.execute(
                        "SELECT source FROM cursor WHERE seen<? AND source>? ORDER BY source LIMIT 256",
                        (cutoff, marker),
                    ).fetchall()
                    if not rows:
                        break
                    marker = rows[-1][0]
                    absent = []
                    for (source,) in rows:
                        parts = source.split("/")
                        file_key = "/".join(parts[:3]) + "/"
                        if (
                            parts[0] not in uncertain_sources
                            and file_key not in live_files
                        ):
                            absent.append((source,))
                    self.db.executemany("DELETE FROM cursor WHERE source=?", absent)
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return count
