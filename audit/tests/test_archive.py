from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from platform_audit.archive import Archive, ArchiveUnsafe

NOW = datetime(2026, 9, 23, tzinfo=timezone.utc)


def client():
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
    return c


def test_rejects_storage_that_cannot_protect_month_of_logs():
    for default in (
        {"Mode": "GOVERNANCE", "Days": 30},
        {"Mode": "COMPLIANCE", "Days": 7},
        {},
    ):
        c = client()
        c.get_object_lock_configuration.return_value["ObjectLockConfiguration"]["Rule"][
            "DefaultRetention"
        ] = default
        with pytest.raises(ArchiveUnsafe):
            Archive(c, "audit-bucket").verify_bucket()
    c = client()
    c.get_bucket_versioning.return_value = {"Status": "Suspended"}
    with pytest.raises(ArchiveUnsafe):
        Archive(c, "audit-bucket").verify_bucket()


def test_archive_retry_is_conditional_and_verifies_existing_hash_and_lock():
    c = client()
    captured = {}

    def upload(**kwargs):
        captured.update(kwargs)
        raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")

    c.put_object.side_effect = upload
    c.head_object.side_effect = lambda **_: {
        "VersionId": "version-1",
        "Metadata": captured["Metadata"],
    }
    c.get_object_retention.return_value = {
        "Retention": {"Mode": "COMPLIANCE", "RetainUntilDate": NOW + timedelta(days=30)}
    }
    a = Archive(c, "audit-bucket")
    batch = {"id": "a" * 32, "created": NOW.timestamp()}
    result = a.put(batch, [{"observed_at": NOW.isoformat(), "actor": None}], NOW)
    assert result["version_id"] == "version-1"
    assert captured["IfNoneMatch"] == "*"
    assert captured["ObjectLockMode"] == "COMPLIANCE"
    assert captured["ObjectLockRetainUntilDate"] == NOW + timedelta(days=30)
    assert not c.delete_object.called
    c.head_object.return_value = {
        "VersionId": "different",
        "Metadata": {"sha256": "wrong"},
    }
    c.head_object.side_effect = None
    with pytest.raises(ArchiveUnsafe):
        a.put(batch, [{"observed_at": NOW.isoformat()}], NOW)


def test_cleanup_skips_fresh_extended_held_and_foreign_records():
    c = client()
    a = Archive(c, "audit-bucket")
    old = NOW - timedelta(days=31)
    c.list_object_versions.return_value = {
        "Versions": [
            {"Key": "platform-audit/" + name, "VersionId": name, "LastModified": old}
            for name in ["expired", "fresh", "extended", "held", "foreign"]
        ],
        "IsTruncated": False,
    }

    def retention(**kw):
        future = kw["VersionId"] in ["fresh", "extended"]
        return {
            "Retention": {
                "Mode": "COMPLIANCE",
                "RetainUntilDate": NOW + timedelta(days=1)
                if future
                else NOW - timedelta(seconds=1),
            }
        }

    c.get_object_retention.side_effect = retention
    c.head_object.side_effect = lambda **kw: {
        "Metadata": {}
        if kw["VersionId"] == "foreign"
        else {"archive-created-at": old.isoformat(), "sha256": "a" * 64, "schema": "1"}
    }
    c.get_object_legal_hold.side_effect = lambda **kw: {
        "LegalHold": {"Status": "ON" if kw["VersionId"] == "held" else "OFF"}
    }
    result = a.sweep(NOW)
    assert result == {"deleted": 1, "scanned": 5, "blocked": 2, "cursor": {}}
    c.delete_object.assert_called_once_with(
        Bucket="audit-bucket", Key="platform-audit/expired", VersionId="expired"
    )


def test_cleanup_returns_progress_and_never_restarts_at_first_page_forever():
    c = client()
    c.list_object_versions.return_value = {
        "Versions": [],
        "IsTruncated": True,
        "NextKeyMarker": "platform-audit/page2",
        "NextVersionIdMarker": "v2",
    }
    result = Archive(c, "audit-bucket").sweep(NOW, max_pages=1)
    assert result["cursor"] == {"key": "platform-audit/page2", "version": "v2"}
    with pytest.raises(ArchiveUnsafe):
        Archive(c, "audit-bucket").sweep(NOW, result["cursor"], max_pages=1)


def test_future_batch_cannot_create_unbounded_retention():
    c = client()
    with pytest.raises(ArchiveUnsafe):
        Archive(c, "audit-bucket").put(
            {"id": "a" * 32, "created": (NOW + timedelta(days=365)).timestamp()},
            [{}],
            NOW,
        )
    c.put_object.assert_not_called()


def test_wrong_local_clock_cannot_extend_object_lock_by_months():
    c = client()
    future = NOW + timedelta(days=90)
    with pytest.raises(ArchiveUnsafe):
        Archive(c, "audit-bucket").put(
            {"id": "a" * 32, "created": future.timestamp()}, [{}], future
        )
    c.put_object.assert_not_called()


def test_cleaner_refuses_bad_clock_before_listing_or_deleting():
    c = client()
    with pytest.raises(ArchiveUnsafe):
        Archive(c, "audit-bucket").sweep(NOW + timedelta(days=31))
    c.list_object_versions.assert_not_called()
    c.delete_object.assert_not_called()
