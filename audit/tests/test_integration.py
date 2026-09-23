"""Opt-in REAL loopback S3 Object Lock tests; never use a cloud/shared endpoint."""

import gzip
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
import socket
import sqlite3
import threading
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

from platform_audit.archive import Archive


@pytest.fixture
def s3():
    endpoint = os.environ.get("AUDIT_TEST_S3_ENDPOINT")
    if not endpoint:
        pytest.skip("dedicated loopback Object Lock server not configured")
    parsed = urlsplit(endpoint)
    assert (
        parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        and parsed.port
        and not parsed.username
    )
    c = boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}),
    )
    bucket = "audit-it-" + uuid.uuid4().hex
    c.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    c.put_object_lock_configuration(
        Bucket=bucket,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 30}},
        },
    )
    # Locked objects cannot be deleted for cleanup through S3. Keep isolated fixture
    # data until its explicitly owned local server/data directory is disposed.
    yield c, bucket, endpoint


def test_real_lock_and_end_to_end_cli(s3, tmp_path):
    c, bucket, endpoint = s3
    fixtures = {
        "jobscheduler": 'INFO: 10.0.0.1:1 - "POST /jobs/12/run?token=SECRET HTTP/1.1" 303 See Other\n',
        "coolify": '[2026-09-23 00:00:00] production.INFO: api.deployment.triggered {"user_id":7,"deployment_uuid":"deployment123","token_name":"SECRET"}\n',
        "signoz": json.dumps(
            {
                "msg": "::RECEIVED-REQUEST::",
                "http.route": "/api/v1/dashboards/{id}",
                "http.response.status_code": 200,
                "response.body": "SECRET",
            }
        )
        + "\n",
    }
    config = f'state_dir = "{tmp_path}/state"\n[archive]\nbucket = "{bucket}"\n'
    for platform, line in fixtures.items():
        path = tmp_path / (platform + ".log")
        path.write_text(line)
        config += f'[[sources]]\nid="{platform}"\nplatform="{platform}"\nenvironment="test"\npath="{path}"\n'
    cfg = tmp_path / "config.toml"
    cfg.write_text(config)
    env = os.environ.copy()
    env["AUDIT_S3_ENDPOINT"] = endpoint
    command = [
        sys.executable,
        "-m",
        "platform_audit.cli",
        "collect",
        "--once",
        "--config",
        str(cfg),
    ]
    one = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
    assert one.returncode == 0, one.stdout + one.stderr
    versions = c.list_object_versions(Bucket=bucket)["Versions"]
    assert len(versions) == 1
    obj = versions[0]
    retention = c.get_object_retention(
        Bucket=bucket, Key=obj["Key"], VersionId=obj["VersionId"]
    )["Retention"]
    assert retention["Mode"] == "COMPLIANCE"
    assert retention["RetainUntilDate"] > datetime.now(timezone.utc) + timedelta(
        days=29, hours=23
    )
    with pytest.raises(ClientError) as denied:
        c.delete_object(Bucket=bucket, Key=obj["Key"], VersionId=obj["VersionId"])
    assert denied.value.response["Error"]["Code"] in {"AccessDenied", "InvalidRequest"}
    assert (
        c.head_object(Bucket=bucket, Key=obj["Key"], VersionId=obj["VersionId"])[
            "VersionId"
        ]
        == obj["VersionId"]
    )
    with pytest.raises(ClientError):
        c.put_object_retention(
            Bucket=bucket,
            Key=obj["Key"],
            VersionId=obj["VersionId"],
            Retention={
                "Mode": "COMPLIANCE",
                "RetainUntilDate": datetime.now(timezone.utc) + timedelta(days=1),
            },
        )
    again = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
    assert (
        again.returncode == 0
        and len(c.list_object_versions(Bucket=bucket)["Versions"]) == 1
    )
    exported = subprocess.run(
        [sys.executable, "-m", "platform_audit.cli", "export", "--config", str(cfg)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert exported.returncode == 0, exported.stderr
    records = [json.loads(x) for x in exported.stdout.splitlines()]
    assert {x["platform"] for x in records} == set(fixtures)
    assert "SECRET" not in exported.stdout
    assert next(x for x in records if x["platform"] == "jobscheduler")["actor"] is None
    assert next(x for x in records if x["platform"] == "coolify")["actor"]["id"] == "7"
    for platform, original in fixtures.items():
        assert (tmp_path / (platform + ".log")).read_text() == original


def test_real_expired_version_cleanup_does_not_touch_fresh_or_foreign(s3):
    c, bucket, _ = s3
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=31)
    body = gzip.compress(b'{"synthetic":true}\n', mtime=0)
    data = {
        "Bucket": bucket,
        "Body": body,
        "ObjectLockMode": "COMPLIANCE",
        "Metadata": {
            "schema": "1",
            "sha256": hashlib.sha256(body).hexdigest(),
            "archive-created-at": old.isoformat(),
        },
    }
    c.put_object(
        Key="platform-audit/expired.jsonl.gz",
        ObjectLockRetainUntilDate=now + timedelta(seconds=2),
        **data,
    )
    c.put_object(
        Key="platform-audit/fresh.jsonl.gz",
        ObjectLockRetainUntilDate=now + timedelta(days=30),
        **data,
    )
    c.put_object(
        Key="outside-prefix/expired.jsonl.gz",
        ObjectLockRetainUntilDate=now + timedelta(seconds=2),
        **data,
    )
    time.sleep(
        2.2
    )  # Short synthetic retention fixture, NOT a claim of waiting 30 real days.
    result = Archive(c, bucket).sweep(datetime.now(timezone.utc))
    assert result["deleted"] == 1
    keys = {x["Key"] for x in c.list_object_versions(Bucket=bucket)["Versions"]}
    assert keys == {"platform-audit/fresh.jsonl.gz", "outside-prefix/expired.jsonl.gz"}


def test_real_archive_retry_does_not_create_extra_versions(s3):
    c, bucket, _ = s3
    now = datetime.now(timezone.utc)
    batch = {"id": uuid.uuid4().hex, "created": now.timestamp()}
    events = [
        {
            "observed_at": now.isoformat(),
            "platform": "jobscheduler",
            "actor": None,
            "action": "job.toggle",
        }
    ]
    a = Archive(c, bucket)
    one = a.put(batch, events, now)
    two = a.put(batch, events, datetime.now(timezone.utc))
    assert one == two
    assert len(c.list_object_versions(Bucket=bucket)["Versions"]) == 1
    original = gzip.compress
    with patch(
        "platform_audit.archive.gzip.compress",
        side_effect=lambda data, mtime: original(data, compresslevel=1, mtime=mtime),
    ):
        assert a.put(batch, events, datetime.now(timezone.utc)) == one
    assert len(c.list_object_versions(Bucket=bucket)["Versions"]) == 1


def test_storage_outage_keeps_durable_operation_and_recovers_without_duplicates(
    s3, tmp_path
):
    c, bucket, endpoint = s3
    log = tmp_path / "app.log"
    content = 'INFO: 10.0.0.1:1 - "POST /jobs/3/delete HTTP/1.1" 303 See Other\n'
    log.write_text(content)
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'state_dir="{tmp_path}/state"\n[archive]\nbucket="{bucket}"\n[[sources]]\nid="jobs"\nplatform="jobscheduler"\nenvironment="test"\npath="{log}"\n'
    )
    command = [
        sys.executable,
        "-m",
        "platform_audit.cli",
        "collect",
        "--once",
        "--config",
        str(cfg),
    ]
    env = os.environ.copy()
    with socket.socket() as reserved:
        reserved.bind(
            ("127.0.0.1", 0)
        )  # Bound but not listening: deterministic refusal.
        env["AUDIT_S3_ENDPOINT"] = "http://127.0.0.1:" + str(reserved.getsockname()[1])
        failed = subprocess.run(
            command, env=env, capture_output=True, text=True, timeout=30
        )
    assert failed.returncode == 1 and "archive_failed" in failed.stdout
    with sqlite3.connect(tmp_path / "state/journal.db") as db:
        assert db.execute("SELECT count(*) FROM event").fetchone()[0] == 1
        batch = db.execute("SELECT id FROM batch").fetchone()[0]
    env["AUDIT_S3_ENDPOINT"] = endpoint
    recovered = subprocess.run(
        command, env=env, capture_output=True, text=True, timeout=30
    )
    assert recovered.returncode == 0 and batch in recovered.stdout
    assert len(c.list_object_versions(Bucket=bucket)["Versions"]) == 1
    assert log.read_text() == content


def test_optional_index_failure_cannot_lose_or_block_locked_archive(s3, tmp_path):
    c, bucket, endpoint = s3
    captured = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            captured.append(
                json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            )
            self.send_response(503)
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        log = tmp_path / "app.log"
        log.write_text('INFO: 10.0.0.1:1 - "POST /jobs/3/run HTTP/1.1" 303 See Other\n')
        cfg = tmp_path / "config.toml"
        cfg.write_text(
            f'state_dir="{tmp_path}/state"\n[archive]\nbucket="{bucket}"\n[index]\nendpoint="http://127.0.0.1:{server.server_port}/v1/logs"\nretention_confirmed_days=30\n[[sources]]\nid="jobs"\nplatform="jobscheduler"\nenvironment="test"\npath="{log}"\n'
        )
        env = os.environ.copy()
        env["AUDIT_S3_ENDPOINT"] = endpoint
        r = subprocess.run(
            [
                sys.executable,
                "-m",
                "platform_audit.cli",
                "collect",
                "--once",
                "--config",
                str(cfg),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode == 0 and "index_failed_archive_retained" in r.stdout
        assert (
            len(c.list_object_versions(Bucket=bucket)["Versions"]) == 1
            and len(captured) == 1
        )
        records = list(
            Archive(c, bucket).export(datetime.now(timezone.utc) - timedelta(hours=1))
        )
        assert len(records) == 1 and records[0]["actor"] is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
