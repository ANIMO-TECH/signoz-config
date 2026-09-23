import io
import json
from unittest.mock import Mock

import pytest

from platform_audit.index import OtlpIndex


def test_index_keeps_unknown_actor_and_detects_partial_rejection():
    index = OtlpIndex("http://127.0.0.1:4318/v1/logs")
    response = Mock()
    response.__enter__ = Mock(
        return_value=io.BytesIO(b'{"partialSuccess":{"rejectedLogRecords":"1"}}')
    )
    response.__exit__ = Mock(return_value=False)
    index.opener.open = Mock(return_value=response)
    with pytest.raises(ValueError):
        index.send(
            [
                {
                    "observed_at": "2026-09-23T00:00:00Z",
                    "event_id": "event1",
                    "platform": "coolify",
                    "actor": None,
                }
            ]
        )
    request = index.opener.open.call_args.args[0]
    body = json.loads(request.data)["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0][
        "body"
    ]["stringValue"]
    assert json.loads(body)["actor"] is None


def test_index_does_not_accept_credentials_in_url_or_redirect_to_unknown_route():
    for url in [
        "https://user:password@host/v1/logs",
        "https://host/v1/logs?token=secret",
        "http://external.example/v1/logs",
        "https://host/delete",
    ]:
        with pytest.raises(ValueError):
            OtlpIndex(url)
