import argparse
import json
import os
import signal
import sys
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import boto3
from botocore.config import Config

from .archive import Archive
from .events import PLATFORMS
from .store import Journal, RETENTION
from .worker import Tailer


def settings(path):
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    ids = set()
    for source in cfg.get("sources", []):
        if source.get("platform") not in PLATFORMS or source.get("environment") not in {
            "prod",
            "test",
        }:
            raise ValueError("source requires platform and explicit environment")
        ident = source.get("id", "")
        import re

        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", ident) or ident in ids:
            raise ValueError("invalid/duplicate source id")
        ids.add(ident)
        if not Path(source.get("path", "")).is_absolute():
            raise ValueError("source paths must be absolute")
        if not isinstance(source.get("include_reads", False), bool):
            raise ValueError("include_reads must be boolean")
    if (
        not 1024 * 1024
        <= int(cfg.get("max_spool_bytes", 64 * 1024 * 1024))
        <= 1024 * 1024 * 1024
    ):
        raise ValueError("spool limit must be between 1 MiB and 1 GiB")
    if not Path(cfg.get("state_dir", "/var/lib/platform-audit")).is_absolute():
        raise ValueError("state_dir must be absolute")
    bucket = cfg["archive"]["bucket"]
    if not bucket or "/" in bucket:
        raise ValueError("invalid archive bucket")
    endpoint = os.getenv("AUDIT_S3_ENDPOINT") or None
    if endpoint:
        url = urlsplit(endpoint)
        if url.username or url.password or url.query or url.fragment:
            raise ValueError("invalid S3 endpoint")
        if url.scheme != "https" and not (
            url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost", "::1"}
        ):
            raise ValueError("S3 requires HTTPS except loopback tests")
    return cfg, endpoint


def client(endpoint):
    # AWS SDK credential chain supports workload identities and separate container secrets.
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        config=Config(
            connect_timeout=3,
            read_timeout=15,
            retries={"max_attempts": 2, "mode": "standard"},
            s3={"addressing_style": "path"},
        ),
    )


def emit(event, **fields):
    print(
        json.dumps(
            {"component": "platform-audit", "event": event, **fields}, sort_keys=True
        ),
        flush=True,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Collect operation logs; archive under 30-day COMPLIANCE lock"
    )
    parser.add_argument(
        "command", choices=["collect", "cleanup", "export", "reindex", "check"]
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--platform", choices=sorted(PLATFORMS))
    parser.add_argument(
        "--since", help="Timezone-qualified ISO timestamp (export only, last 30 days)"
    )
    parser.add_argument(
        "--github",
        action="store_true",
        help="Resolve approved repo+commit links during export; does not infer actors",
    )
    args = parser.parse_args(argv)
    try:
        cfg, endpoint = settings(args.config)
    except Exception as exc:
        emit("configuration_error", error_type=type(exc).__name__)
        return 2
    if args.command == "collect" and not cfg.get("sources"):
        emit("configuration_error", error_type="NoSources")
        return 2
    try:
        archive = Archive(
            client(endpoint),
            cfg["archive"]["bucket"],
            cfg["archive"].get("prefix", "platform-audit/"),
        )
    except Exception as exc:
        emit("archive_configuration_error", error_type=type(exc).__name__)
        return 2
    now = lambda: datetime.now(timezone.utc)
    from .index import OtlpIndex

    try:
        index_cfg = cfg.get("index", {})
        if not isinstance(index_cfg.get("allow_http", False), bool):
            raise ValueError("index allow_http must be boolean")
        if isinstance(index_cfg.get("retention_confirmed_days"), bool):
            raise ValueError("index retention must be a day count")
        if (
            index_cfg.get("endpoint")
            and not 1 <= int(index_cfg.get("retention_confirmed_days", 0)) <= 30
        ):
            raise ValueError(
                "verify index retention is at most 30 days before enabling the optional copy"
            )
        index = (
            OtlpIndex(index_cfg["endpoint"], index_cfg.get("allow_http", False))
            if index_cfg.get("endpoint")
            else None
        )
    except Exception as exc:
        emit("index_disabled_configuration_error", error_type=type(exc).__name__)
        index = None
    if args.command == "check":
        try:
            archive.verify_bucket()
        except Exception as exc:
            emit("archive_unsafe", error_type=type(exc).__name__)
            return 2
        emit("archive_ready", retention_days=30)
        return 0
    if args.command in {"export", "reindex"}:
        since = (
            datetime.fromisoformat(args.since.replace("Z", "+00:00"))
            if args.since
            else now() - RETENTION
        )
        if since.tzinfo is None:
            parser.error("--since requires timezone")
        since = max(since, now() - RETENTION)
        from .github import GitHubLinks

        links = GitHubLinks(cfg.get("github_repositories", [])) if args.github else None
        pending = []
        if args.command == "reindex" and not index:
            emit("index_not_configured")
            return 2
        for event in archive.export(since, args.platform):
            if args.command == "export":
                print(
                    json.dumps(
                        links.enrich(event) if links else event, ensure_ascii=False
                    )
                )
            else:
                pending.append(event)
                if len(pending) == 500:
                    index.send(pending)
                    pending = []
        if pending:
            index.send(pending)
        return 0
    stop = False

    def stopped(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, stopped)
    signal.signal(signal.SIGINT, stopped)
    state = Path(cfg.get("state_dir", "/var/lib/platform-audit"))
    if state.is_symlink():
        emit("unsafe_state_directory")
        return 2
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = state.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        emit("unsafe_state_directory")
        return 2
    # Exactly one process per role/state directory. A second worker cannot double-consume.
    import fcntl

    lock = open(state / (args.command + ".lock"), "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        emit("already_running")
        lock.close()
        return 2
    journal = (
        Journal(
            state / "journal.db",
            max_bytes=int(cfg.get("max_spool_bytes", 64 * 1024 * 1024)),
        )
        if args.command == "collect"
        else None
    )
    tailer = Tailer(journal, cfg.get("sources", [])) if journal else None
    interval = 60 if journal else 3600
    exit_code = 0
    try:
        while not stop:
            started = time.monotonic()
            errors = 0
            if journal:
                try:
                    expired = journal.expire(now(), tailer.cursor_inventory())
                    if expired:
                        emit("expired_unarchived_events", count=expired)
                    stats = tailer.poll(now())
                    emit("collected", **stats)
                    if stats["unavailable"]:
                        errors += 1
                except Exception as exc:
                    emit("collection_failed", error_type=type(exc).__name__)
                    errors += 1
                # Flush even if input is full/unavailable; this can release backpressure.
                try:
                    for _ in range(20):
                        if stop:
                            break
                        batch = journal.prepare(now())
                        if not batch:
                            break
                        events = journal.batch_events(batch["id"])
                        archive.put(batch, events, now())
                        journal.ack(batch["id"])
                        emit("archived", batch_id=batch["id"])
                        if index:
                            try:
                                index.send(events)
                            except Exception as exc:
                                emit(
                                    "index_failed_archive_retained",
                                    batch_id=batch["id"],
                                    error_type=type(exc).__name__,
                                )
                except Exception as exc:
                    emit("archive_failed", error_type=type(exc).__name__)
                    errors += 1
            else:
                try:
                    cursor_file = state / "cleanup-cursor.json"
                    try:
                        cursor = (
                            json.loads(cursor_file.read_text())
                            if cursor_file.exists()
                            else {}
                        )
                        if not isinstance(cursor, dict):
                            raise ValueError("invalid cursor")
                    except (ValueError, OSError):
                        cursor = {}
                        emit("cleanup_cursor_reset")
                    result = archive.sweep(now(), cursor)
                    temporary = cursor_file.with_suffix(".tmp")
                    temporary.write_text(json.dumps(result.pop("cursor")))
                    os.chmod(temporary, 0o600)
                    os.replace(temporary, cursor_file)
                    emit("retention_sweep", **result)
                except Exception as exc:
                    emit("cleanup_failed", error_type=type(exc).__name__)
                    errors += 1
            exit_code = 1 if errors else 0
            if args.once:
                break
            while not stop and time.monotonic() - started < interval:
                time.sleep(0.2)
    finally:
        if journal:
            journal.db.close()
        lock.close()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
