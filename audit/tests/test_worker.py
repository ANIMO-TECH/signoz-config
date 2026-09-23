from datetime import datetime, timedelta, timezone

from platform_audit.store import Journal
from platform_audit.worker import Tailer

NOW = datetime(2026, 9, 23, tzinfo=timezone.utc)
LINE = b'INFO: 10.0.0.1:1 - "POST /jobs/12/run HTTP/1.1" 303 See Other\n'


def setup(tmp_path):
    sources = [
        dict(
            id="jobs-prod",
            platform="jobscheduler",
            environment="prod",
            path=str(tmp_path / "*.log*"),
        )
    ]
    return sources


def test_partial_write_restart_and_rename_rotation_do_not_duplicate(tmp_path):
    path = tmp_path / "app.log"
    path.write_bytes(LINE + LINE[:10])
    with Journal(tmp_path / "j.db") as j:
        t = Tailer(j, setup(tmp_path))
        assert t.poll(NOW)["events"] == 1
    with Journal(tmp_path / "j.db") as j:
        t = Tailer(j, setup(tmp_path))
        assert t.poll(NOW)["events"] == 0
        with path.open("ab") as f:
            f.write(LINE[10:])
        assert t.poll(NOW)["events"] == 1
        path.rename(tmp_path / "app.log.1")
        path.write_bytes(LINE)
        assert t.poll(NOW)["events"] == 1
        assert len(j.batch_events(j.prepare(NOW)["id"])) == 3


def test_huge_line_makes_bounded_progress_without_interpreting_fragments(tmp_path):
    path = tmp_path / "app.log"
    path.write_bytes(b"x" * 2500000 + b"\n" + LINE)
    with Journal(tmp_path / "j.db") as j:
        t = Tailer(j, setup(tmp_path))
        results = [t.poll(NOW) for _ in range(4)]
        assert sum(x["events"] for x in results) == 1
        assert sum(x["oversized"] for x in results) > 0


def test_source_symlink_never_reads_unapproved_file(tmp_path):
    secret = tmp_path / "not-a-log"
    secret.write_bytes(LINE)
    (tmp_path / "app.log").symlink_to(secret)
    with Journal(tmp_path / "j.db") as j:
        result = Tailer(j, setup(tmp_path)).poll(NOW)
        assert result["events"] == 0 and result["unavailable"] == 1


def test_retention_does_not_mutate_prepared_batch_during_retry(tmp_path):
    with Journal(tmp_path / "j.db") as j:
        e = {"observed_at": NOW.isoformat(), "actor": None}
        j.accept("old", 1, e, NOW - timedelta(days=30) + timedelta(seconds=5))
        j.accept("fresh", 1, e, NOW - timedelta(days=30) + timedelta(seconds=6))
        batch = j.prepare(NOW)
        before = j.batch_events(batch["id"])
        assert j.expire(NOW + timedelta(seconds=5.5)) == 0
        assert j.batch_events(batch["id"]) == before
        assert j.expire(NOW + timedelta(seconds=7)) == 2


def test_unterminated_oversized_line_cannot_turn_its_suffix_into_an_operation(tmp_path):
    path = tmp_path / "app.log"
    path.write_bytes(b"x" * 70000)
    with Journal(tmp_path / "j.db") as j:
        t = Tailer(j, setup(tmp_path))
        assert t.poll(NOW)["events"] == 0
        with path.open("ab") as f:
            f.write(LINE + LINE)
        assert (
            t.poll(NOW)["events"] == 1
        )  # First apparent LINE was still the discarded suffix.


def test_poll_budget_is_global_and_files_do_not_starve(tmp_path):
    (tmp_path / "a.log").write_bytes(LINE * 3)
    (tmp_path / "b.log").write_bytes(LINE)
    with Journal(tmp_path / "j.db") as j:
        t = Tailer(j, setup(tmp_path), max_lines=1)
        assert t.poll(NOW)["events"] == 1
        assert t.poll(NOW)["events"] == 1
        # Second poll starts the second file instead of exhausting the busy first one.
        assert len(list(j.db.execute("SELECT * FROM cursor"))) == 2


def test_observed_truncation_resets_incomplete_discard_state(tmp_path):
    path = tmp_path / "app.log"
    path.write_bytes(LINE + b"x" * 70000)
    with Journal(tmp_path / "j.db") as j:
        t = Tailer(j, setup(tmp_path))
        assert t.poll(NOW)["events"] == 1
        path.write_bytes(LINE)
        r = t.poll(NOW)
        assert r["truncations"] == 1 and r["events"] == 1
