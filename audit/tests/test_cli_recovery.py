from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from platform_audit import cli
from platform_audit.store import Journal

NOW = datetime(2026, 9, 23, tzinfo=timezone.utc)


@pytest.mark.parametrize("signature_rejected", [False, True])
def test_bad_local_clock_does_not_expire_pending_evidence(
    tmp_path, monkeypatch, signature_rejected
):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    path = tmp_path / "app.log"
    path.write_text('INFO: 192.0.2.1:1 - "POST /jobs/2/run HTTP/1.1" 303 See Other\n')
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'state_dir="{state}"\n[archive]\nbucket="audit-test"\n[[sources]]\nid="jobs"\nplatform="jobscheduler"\nenvironment="prod"\npath="{path}"\n'
    )
    with Journal(state / "journal.db") as j:
        j.accept(
            "jobs/1/1/signature",
            1,
            {"observed_at": NOW.isoformat(), "platform": "jobscheduler"},
            NOW,
        )

    class WrongClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW + timedelta(days=31)

    c = Mock()
    c.get_bucket_versioning.return_value = {
        "Status": "Enabled",
        "ResponseMetadata": {"HTTPHeaders": {"date": "Wed, 23 Sep 2026 00:00:00 GMT"}},
    }
    c.get_object_lock_configuration.return_value = {
        "ObjectLockConfiguration": {
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 30}},
        }
    }
    if signature_rejected:
        c.get_bucket_versioning.side_effect = ClientError(
            {"Error": {"Code": "RequestTimeTooSkewed"}}, "GetBucketVersioning"
        )
    monkeypatch.setattr(cli, "datetime", WrongClock)
    monkeypatch.setattr(cli, "client", lambda endpoint: c)
    monkeypatch.setattr(cli.signal, "signal", lambda *args: None)
    assert cli.main(["collect", "--once", "--config", str(cfg)]) == 1
    with Journal(state / "journal.db") as j:
        assert j.db.execute("SELECT count(*) FROM event").fetchone()[0] == 1


def test_storage_outage_defers_expiry_and_sealing_but_keeps_bounded_intake(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    path = tmp_path / "app.log"
    path.write_text('INFO: 192.0.2.1:1 - "POST /jobs/1/run HTTP/1.1" 303 See Other\n')
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'state_dir="{state}"\n[archive]\nbucket="audit-test"\n[[sources]]\nid="jobs"\nplatform="jobscheduler"\nenvironment="prod"\npath="{path}"\n'
    )
    with Journal(state / "journal.db") as j:
        j.accept(
            "old",
            1,
            {"observed_at": (NOW - timedelta(days=31)).isoformat()},
            NOW - timedelta(days=31),
        )
    c = Mock()
    c.get_bucket_versioning.side_effect = OSError("unavailable")
    monkeypatch.setattr(cli, "client", lambda endpoint: c)
    monkeypatch.setattr(cli.signal, "signal", lambda *args: None)
    assert cli.main(["collect", "--once", "--config", str(cfg)]) == 1
    with Journal(state / "journal.db") as j:
        assert j.db.execute("SELECT count(*) FROM event").fetchone()[0] == 2
        assert j.db.execute("SELECT count(*) FROM batch").fetchone()[0] == 0


def test_wall_clock_step_after_validation_does_not_corrupt_receipt_time(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    path = tmp_path / "app.log"
    path.write_text('INFO: 192.0.2.1:1 - "POST /jobs/1/run HTTP/1.1" 303 See Other\n')
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'state_dir="{state}"\n[archive]\nbucket="audit-test"\n[[sources]]\nid="jobs"\nplatform="jobscheduler"\nenvironment="prod"\npath="{path}"\n'
    )

    class SteppingClock(datetime):
        reads = 0

        @classmethod
        def now(cls, tz=None):
            cls.reads += 1
            return NOW if cls.reads <= 2 else NOW + timedelta(days=31)

    c = Mock()
    c.get_bucket_versioning.return_value = {
        "Status": "Enabled",
        "ResponseMetadata": {"HTTPHeaders": {"date": "Wed, 23 Sep 2026 00:00:00 GMT"}},
    }
    c.get_object_lock_configuration.return_value = {
        "ObjectLockConfiguration": {
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 30}},
        }
    }
    captured = []
    monkeypatch.setattr(cli, "datetime", SteppingClock)
    monkeypatch.setattr(cli.time, "monotonic", lambda: 0)
    monkeypatch.setattr(cli, "client", lambda endpoint: c)
    monkeypatch.setattr(cli.signal, "signal", lambda *args: None)
    monkeypatch.setattr(
        cli.Archive,
        "put",
        lambda self, batch, events, now: captured.append((batch, events, now)),
    )
    assert cli.main(["collect", "--once", "--config", str(cfg)]) == 0
    assert len(captured) == 1
    batch, events, observed = captured[0]
    assert batch["created"] == NOW.timestamp() and observed == NOW
    assert (
        datetime.fromisoformat(events[0]["observed_at"].replace("Z", "+00:00")) == NOW
    )
