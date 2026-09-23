"""Read-only file tailing; never write to source files or contact source platforms."""

import glob
import hashlib
import os
import stat
from datetime import datetime, timezone

from .events import MAX_LINE, normalize


class Tailer:
    def __init__(self, journal, sources, max_lines=2000):
        self.journal, self.sources, self.max_lines = journal, sources, max_lines
        self.next_file = 0

    def cursor_inventory(self):
        """Metadata-only liveness check; an unavailable mount cannot retire cursors."""
        live_files, uncertain_sources = set(), set()
        for source in self.sources:
            paths = glob.glob(source["path"])
            if not paths or len(paths) > 256:
                uncertain_sources.add(source["id"])
                continue
            for path in paths:
                try:
                    info = os.stat(path, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode):
                        uncertain_sources.add(source["id"])
                        continue
                    live_files.add(f"{source['id']}/{info.st_dev}/{info.st_ino}/")
                except OSError:
                    uncertain_sources.add(source["id"])
        return live_files, uncertain_sources

    def poll(self, now=None):
        now = now or datetime.now(timezone.utc)
        stats = dict(
            lines=0, events=0, oversized=0, unavailable=0, truncations=0, bytes=0
        )
        max_bytes = 4 * 1024 * 1024
        candidates = []
        for source in self.sources:
            files = sorted(glob.glob(source["path"]))
            if len(files) > 256:
                stats["unavailable"] += 1
                continue
            if not files:
                stats["unavailable"] += 1
            for path in files:
                candidates.append((source, path))
        if not candidates:
            return stats
        start_index = self.next_file % len(candidates)
        for step in range(len(candidates)):
            if (
                stats["lines"] + stats["oversized"] >= self.max_lines
                or stats["bytes"] >= max_bytes
            ):
                return stats
            index = (start_index + step) % len(candidates)
            source, path = candidates[index]
            self.next_file = (index + 1) % len(candidates)
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError:
                stats["unavailable"] += 1
                continue
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    stats["unavailable"] += 1
                    continue
                # The first completed line identifies copy-truncate/inode reuse without
                # changing identity when a short, currently incomplete file grows.
                first = stream.readline(MAX_LINE + 1)
                stats["bytes"] += len(first)
                if not first.endswith(b"\n") and len(first) <= MAX_LINE:
                    continue
                signature = hashlib.sha256(first).hexdigest()[:20]
                ident = f"{source['id']}/{info.st_dev}/{info.st_ino}/{signature}"
                offset = self.journal.offset(ident)
                reset = info.st_size < offset
                if reset:
                    offset = 0
                    stats["truncations"] += 1
                stream.seek(offset)
                discarding = False if reset else self.journal.discarding(ident)
                for _ in range(self.max_lines):
                    if (
                        stats["lines"] + stats["oversized"] >= self.max_lines
                        or stats["bytes"] >= max_bytes
                    ):
                        return stats
                    start = stream.tell()
                    raw = stream.readline(MAX_LINE + 1)
                    stats["bytes"] += len(raw)
                    if not raw:
                        break
                    if discarding or len(raw) > MAX_LINE:
                        # Both per-line discard and total poll IO have fixed budgets.
                        remaining = min(1024 * 1024, max_bytes - stats["bytes"])
                        terminated = raw.endswith(b"\n")
                        while raw and not terminated and remaining > 0:
                            raw = stream.readline(min(MAX_LINE + 1, remaining))
                            remaining -= len(raw)
                            stats["bytes"] += len(raw)
                            terminated = raw.endswith(b"\n")
                        discarding = not terminated
                        self.journal.accept(
                            ident, stream.tell(), None, now, discarding=discarding
                        )
                        stats["oversized"] += 1
                        if discarding:
                            break
                        continue
                    if not raw.endswith(b"\n"):
                        stream.seek(start)
                        break
                    event = normalize(
                        source["platform"],
                        raw.decode("utf-8", errors="replace"),
                        now,
                        source.get("include_reads", False),
                    )
                    if event:
                        event["instance"] = source["id"]
                        event["instance_environment"] = source["environment"]
                    self.journal.accept(ident, stream.tell(), event, now)
                    stats["lines"] += 1
                    stats["events"] += bool(event)
                # Touch EOF cursors so a stable file isn't replayed after state retention.
                self.journal.accept(
                    ident, self.journal.offset(ident), None, now, discarding=discarding
                )
        return stats
