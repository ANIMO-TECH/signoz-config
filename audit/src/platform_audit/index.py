"""Optional SigNoz/OTLP searchable copy. Object Lock archive remains authoritative."""

import json
import os
import urllib.request
from datetime import datetime
from urllib.parse import urlsplit

from .github import NoRedirect


class OtlpIndex:
    def __init__(self, endpoint, allow_http=False):
        url = urlsplit(endpoint)
        if (
            url.username
            or url.password
            or url.query
            or url.fragment
            or not url.hostname
        ):
            raise ValueError("invalid OTLP endpoint")
        if url.scheme != "https" and not (
            url.scheme == "http"
            and (allow_http or url.hostname in {"127.0.0.1", "localhost", "::1"})
        ):
            raise ValueError(
                "OTLP requires HTTPS or explicit internal HTTP configuration"
            )
        if url.path != "/v1/logs":
            raise ValueError("OTLP endpoint must end in /v1/logs")
        self.endpoint = endpoint
        self.opener = urllib.request.build_opener(NoRedirect())

    def send(self, events):
        if not events:
            return
        logs = []
        for event in events:
            timestamp = datetime.fromisoformat(
                event["observed_at"].replace("Z", "+00:00")
            )
            logs.append(
                {
                    "timeUnixNano": str(int(timestamp.timestamp() * 1000000000)),
                    "severityNumber": 9,
                    "severityText": "INFO",
                    "body": {
                        "stringValue": json.dumps(
                            event, ensure_ascii=False, separators=(",", ":")
                        )
                    },
                    "attributes": [
                        {
                            "key": "audit.event_id",
                            "value": {"stringValue": event["event_id"]},
                        },
                        {
                            "key": "audit.platform",
                            "value": {"stringValue": event["platform"]},
                        },
                    ],
                }
            )
        payload = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": "internal-platform-audit"},
                            }
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "platform-audit", "version": "0.1.0"},
                            "logRecords": logs,
                        }
                    ],
                }
            ]
        }
        body = json.dumps(payload, separators=(",", ":")).encode()
        if len(body) > 16 * 1024 * 1024:
            raise ValueError("index batch too large")
        headers = {"Content-Type": "application/json"}
        if token := os.getenv("AUDIT_OTLP_TOKEN"):
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(
            self.endpoint, data=body, headers=headers, method="POST"
        )
        with self.opener.open(request, timeout=3) as response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError("index response too large")
            result = json.loads(raw) if raw else {}
            if int(result.get("partialSuccess", {}).get("rejectedLogRecords", 0)):
                raise ValueError("index rejected part of the batch")
