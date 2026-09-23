from datetime import datetime, timedelta, timezone

import pytest

from platform_audit.store import Journal, Backpressure

NOW = datetime(2026, 9, 23, tzinfo=timezone.utc)


def event():
    return {
        "observed_at": NOW.isoformat(),
        "platform": "jobscheduler",
        "action": "job.delete",
        "actor": None,
    }


def test_event_and_cursor_are_durable_together_and_retries_keep_batch(tmp_path):
    path = tmp_path / "journal.db"
    with Journal(path) as j:
        j.accept("source/inode", 123, event(), NOW)
        batch = j.prepare(NOW)
    with Journal(path) as j:
        assert j.offset("source/inode") == 123
        assert j.prepare(NOW)["id"] == batch["id"]
        assert len(j.batch_events(batch["id"])) == 1
        j.ack(batch["id"])
        assert j.prepare(NOW) is None
        assert j.offset("source/inode") == 123


def test_full_spool_does_not_advance_cursor_or_discard_new_operation(tmp_path):
    with Journal(tmp_path / "j.db", max_bytes=200) as j:
        j.accept("f", 10, event(), NOW)
        with pytest.raises(Backpressure):
            j.accept("f", 20, event(), NOW)
        assert j.offset("f") == 10


def test_30_day_cleanup_never_deletes_a_fresh_record(tmp_path):
    with Journal(tmp_path / "j.db") as j:
        j.accept("old", 1, event(), NOW - timedelta(days=31))
        j.accept("new", 2, event(), NOW - timedelta(days=29))
        assert j.expire(NOW) == 1
        batch = j.prepare(NOW)
        assert len(j.batch_events(batch["id"])) == 1


def test_empty_or_ignored_line_can_checkpoint_without_creating_operation(tmp_path):
    with Journal(tmp_path / "j.db") as j:
        j.accept("f", 42, None, NOW)
        assert j.offset("f") == 42 and j.prepare(NOW) is None


def test_delayed_upload_does_not_restart_the_thirty_day_clock(tmp_path):
    received = NOW - timedelta(days=20)
    with Journal(tmp_path / "j.db") as j:
        j.accept("old", 1, event(), received)
        j.accept("fresh", 1, event(), NOW)
        batch = j.prepare(NOW)
        assert batch["created"] == received.timestamp()
        assert len(j.batch_events(batch["id"])) == 1
