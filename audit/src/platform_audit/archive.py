"""S3-compatible immutable archive. Writer and retention cleaner use separate roles."""

import gzip
import hashlib
import json
import re
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime

from botocore.exceptions import ClientError

from .store import RETENTION


class ArchiveUnsafe(RuntimeError):
    pass


class Archive:
    def __init__(self, client, bucket, prefix="platform-audit/"):
        if not re.fullmatch(r"[A-Za-z0-9/_-]{1,120}/", prefix) or ".." in prefix:
            raise ValueError("archive prefix must be a nonempty dedicated directory")
        self.client, self.bucket, self.prefix = client, bucket, prefix

    def verify_bucket(self):
        versioning = self.client.get_bucket_versioning(Bucket=self.bucket)
        lock = self.client.get_object_lock_configuration(Bucket=self.bucket).get(
            "ObjectLockConfiguration", {}
        )
        default = lock.get("Rule", {}).get("DefaultRetention", {})
        if (
            versioning.get("Status") != "Enabled"
            or lock.get("ObjectLockEnabled") != "Enabled"
            or default != {"Mode": "COMPLIANCE", "Days": 30}
        ):
            raise ArchiveUnsafe(
                "archive requires versioning and default COMPLIANCE 30-day retention"
            )
        try:
            server_time = parsedate_to_datetime(
                versioning["ResponseMetadata"]["HTTPHeaders"]["date"]
            )
        except (KeyError, ValueError, TypeError):
            raise ArchiveUnsafe("archive server time unavailable") from None
        return server_time

    def put(self, batch, events, now):
        created = datetime.fromtimestamp(batch["created"], timezone.utc)
        until = created + RETENTION
        if created > now or not re.fullmatch(r"[a-f0-9]{32}", batch["id"]):
            raise ArchiveUnsafe("invalid batch identity or future creation time")
        if until.microsecond:
            until = until.replace(microsecond=0) + timedelta(seconds=1)
        if until <= now:
            raise ArchiveUnsafe("batch retention window expired")
        server_time = self.verify_bucket()
        if abs((server_time - now).total_seconds()) > 300:
            raise ArchiveUnsafe("clock differs from storage by more than five minutes")
        raw = b"".join(
            (
                json.dumps(e, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode()
            for e in events
        )
        if not raw or len(raw) > 16 * 1024 * 1024:
            raise ValueError("invalid batch size")
        body = gzip.compress(raw, mtime=0)
        # Content hash stays stable across gzip/zlib versions during recovery.
        digest = hashlib.sha256(raw).hexdigest()
        key = self.prefix + created.strftime("%Y/%m/%d/") + batch["id"] + ".jsonl.gz"
        try:
            result = self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType="application/x-ndjson",
                ContentEncoding="gzip",
                Metadata={
                    "sha256": digest,
                    "schema": "1",
                    "archive-created-at": created.isoformat(),
                },
                IfNoneMatch="*",
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=until,
            )
            version = result.get("VersionId")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in (
                "PreconditionFailed",
                "412",
            ):
                raise
            version = None
        args = dict(Bucket=self.bucket, Key=key)
        if version:
            args["VersionId"] = version
        head = self.client.head_object(**args)
        version = head.get("VersionId") or version
        if (
            not version
            or version == "null"
            or head.get("Metadata", {}).get("sha256") != digest
        ):
            raise ArchiveUnsafe("archive verification failed")
        retention = self.client.get_object_retention(
            Bucket=self.bucket, Key=key, VersionId=version
        ).get("Retention", {})
        if (
            retention.get("Mode") != "COMPLIANCE"
            or retention.get(
                "RetainUntilDate", datetime.min.replace(tzinfo=timezone.utc)
            )
            < until
        ):
            raise ArchiveUnsafe("archive retention verification failed")
        return {
            "key": key,
            "version_id": version,
            "sha256": digest,
            "retain_until": until.isoformat(),
        }

    def sweep(self, now, cursor=None, max_pages=10):
        """Delete only expired immutable versions. Return durable pagination progress."""
        self.verify_bucket()
        cursor = cursor or {}
        deleted = scanned = blocked = 0
        for _ in range(max_pages):
            args = dict(Bucket=self.bucket, Prefix=self.prefix, MaxKeys=1000)
            if cursor.get("key"):
                args["KeyMarker"] = cursor["key"]
            if cursor.get("version"):
                args["VersionIdMarker"] = cursor["version"]
            result = self.client.list_object_versions(**args)
            for obj in result.get("Versions", []):
                scanned += 1
                key, version = obj["Key"], obj["VersionId"]
                if not key.startswith(self.prefix) or version == "null":
                    blocked += 1
                    continue
                # Old object age alone is insufficient: a retention extension/legal hold wins.
                retention = self.client.get_object_retention(
                    Bucket=self.bucket, Key=key, VersionId=version
                ).get("Retention", {})
                if retention.get("Mode") != "COMPLIANCE" or not retention.get(
                    "RetainUntilDate"
                ):
                    blocked += 1
                    continue
                if retention["RetainUntilDate"] > now:
                    continue
                head = self.client.head_object(
                    Bucket=self.bucket, Key=key, VersionId=version
                )
                metadata = head.get("Metadata", {})
                try:
                    created = datetime.fromisoformat(metadata["archive-created-at"])
                except (KeyError, ValueError):
                    blocked += 1
                    continue
                if (
                    created.tzinfo is None
                    or metadata.get("schema") != "1"
                    or not re.fullmatch(r"[a-f0-9]{64}", metadata.get("sha256", ""))
                ):
                    blocked += 1
                    continue
                if (
                    created + RETENTION > now
                    or retention["RetainUntilDate"] < created + RETENTION
                ):
                    blocked += 1
                    continue
                try:
                    hold = self.client.get_object_legal_hold(
                        Bucket=self.bucket, Key=key, VersionId=version
                    ).get("LegalHold", {})
                except ClientError as exc:
                    # MinIO reports absent legal-hold configuration this way even when
                    # the SAME version's retention was successfully verified above.
                    if (
                        exc.response.get("Error", {}).get("Code")
                        != "NoSuchObjectLockConfiguration"
                    ):
                        raise
                    hold = {"Status": "OFF"}
                if hold.get("Status") == "ON":
                    blocked += 1
                    continue
                try:
                    self.client.delete_object(
                        Bucket=self.bucket, Key=key, VersionId=version
                    )
                    deleted += 1
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") in (
                        "AccessDenied",
                        "InvalidRequest",
                    ):
                        blocked += 1
                    else:
                        raise
            if not result.get("IsTruncated"):
                cursor = {}
                break
            following = {
                "key": result.get("NextKeyMarker"),
                "version": result.get("NextVersionIdMarker"),
            }
            if not following["key"] or following == cursor:
                raise ArchiveUnsafe("invalid archive pagination")
            cursor = following
        return dict(deleted=deleted, scanned=scanned, blocked=blocked, cursor=cursor)

    def export(self, since, platform=None):
        # Read versions so a delete marker cannot silently hide a retained audit object.
        pager = self.client.get_paginator("list_object_versions")
        for page in pager.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Versions", []):
                response = self.client.get_object(
                    Bucket=self.bucket, Key=obj["Key"], VersionId=obj["VersionId"]
                )
                stream = response["Body"]
                try:
                    body = stream.read(16 * 1024 * 1024 + 1)
                finally:
                    stream.close()
                if len(body) > 16 * 1024 * 1024:
                    raise ArchiveUnsafe("archive object exceeds read limit")
                import io

                with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
                    raw = gz.read(16 * 1024 * 1024 + 1)
                if len(raw) > 16 * 1024 * 1024:
                    raise ArchiveUnsafe("archive payload exceeds read limit")
                if hashlib.sha256(raw).hexdigest() != response.get("Metadata", {}).get(
                    "sha256"
                ):
                    raise ArchiveUnsafe("archive checksum mismatch")
                for line in raw.splitlines():
                    event = json.loads(line)
                    observed = datetime.fromisoformat(
                        event["observed_at"].replace("Z", "+00:00")
                    )
                    if observed >= since and (
                        not platform or event["platform"] == platform
                    ):
                        yield event
