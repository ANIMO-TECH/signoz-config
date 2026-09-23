import json
from datetime import datetime, timezone

from platform_audit.events import normalize

NOW = datetime(2026, 9, 23, tzinfo=timezone.utc)


def test_unknown_user_does_not_prevent_recording_and_secrets_are_dropped():
    line = 'INFO: 100.64.1.2:123 - "POST /jobs/12/toggle?token=SECRET HTTP/1.1" 303 See Other'
    e = normalize("jobscheduler", line, NOW)
    assert e["action"] == "job.toggle"
    assert e["resource"] == {"type": "job", "id": "12"}
    assert e["actor"] is None
    assert e["outcome"] == "request_completed"
    assert e["peer_ip"] == "100.64.1.2"
    assert "SECRET" not in json.dumps(e)


def test_coolify_native_event_preserves_keys_without_claiming_deploy_success():
    ctx = dict(
        event="api.deployment.triggered",
        user_id=7,
        token_id=3,
        ip="10.0.0.1",
        deployment_uuid="deployment123",
        application_uuid="application123",
        token_name="SECRET",
        authorization="SECRET",
        message="SECRET",
    )
    e = normalize(
        "coolify",
        "[2026-09-23 00:00:00] production.INFO: api.deployment.triggered "
        + json.dumps(ctx),
        NOW,
    )
    assert e["actor"] == {"type": "api_credential", "id": "3", "owner_id": "7"}
    assert e["deployment_id"] == "deployment123"
    assert e["outcome"] == "accepted"
    assert "SECRET" not in json.dumps(e)


def test_laravel_empty_extra_suffix_and_source_clock():
    line = '[2026-09-22 23:59:00] production.INFO: api.deployment.triggered {"deployment_uuid":"deployment123"} []'
    e = normalize("coolify", line, NOW)
    assert e["deployment_id"] == "deployment123"
    assert e["source_time"] == {"value": "2026-09-22T23:59:00", "timezone_known": False}
    assert e["observed_at"] == "2026-09-23T00:00:00Z"


def test_signoz_query_post_is_not_a_change_but_dashboard_put_is():
    base = {
        "msg": "::RECEIVED-REQUEST::",
        "client.address": "10.2.0.1:123",
        "http.response.status_code": 200,
        "http.request.method": "POST",
        "http.route": "/api/v4/query_range",
        "response.body": "SECRET",
    }
    assert normalize("signoz", json.dumps(base), NOW) is None
    base.update({"http.route": "/api/v1/dashboards/{id}", "http.request.method": "PUT"})
    e = normalize("signoz", json.dumps(base), NOW)
    assert e["action"] == "dashboard.update"
    assert e["actor"] is None
    assert e["resource"]["id"] is None
    assert "SECRET" not in json.dumps(e)


def test_signoz_old_logger_without_method_records_uncertainty():
    e = normalize(
        "signoz",
        json.dumps(
            {
                "msg": "::RECEIVED-REQUEST::",
                "http.route": "/api/v1/dashboards/{id}",
                "http.response.status_code": 200,
            }
        ),
        NOW,
    )
    assert e["action"] == "dashboard.request"
    assert e["method"] is None
    assert e["outcome"] == "request_completed"


def test_livewire_is_an_interaction_not_a_fabricated_deploy():
    e = normalize(
        "coolify",
        json.dumps(
            {
                "RequestMethod": "POST",
                "RequestPath": "/livewire/update?secret=x",
                "ClientHost": "10.0.0.1",
                "DownstreamStatus": 200,
            }
        ),
        NOW,
    )
    assert e["action"] == "ui.interaction"
    assert e["actor"] is None
    assert "secret" not in json.dumps(e)


def test_docker_envelope_and_malformed_input():
    raw = 'INFO: 127.0.0.1:123 - "POST /jobs/2/delete HTTP/1.1" 400 Bad Request'
    assert (
        normalize(
            "jobscheduler",
            json.dumps({"log": raw, "time": "2026-09-23T00:00:00Z"}),
            NOW,
        )["outcome"]
        == "rejected"
    )
    for line in ["{bad", "", "SECRET", "x" * 100000]:
        assert normalize("jobscheduler", line, NOW) is None


def test_source_time_does_not_control_retention_and_headers_do_not_set_actor():
    e = normalize(
        "coolify",
        json.dumps(
            {
                "RequestMethod": "POST",
                "RequestPath": "/deploy",
                "StartUTC": "2099-01-01T00:00:00Z",
                "DownstreamStatus": 200,
                "request_X-User-Id": "attacker",
                "request_Authorization": "SECRET",
            }
        ),
        NOW,
    )
    assert e["observed_at"] == "2026-09-23T00:00:00Z"
    assert e["actor"] is None
    assert "SECRET" not in json.dumps(e)


def test_pathological_json_does_not_poison_the_tail_cursor():
    line = '{"x":' + ("[" * 5000) + "0" + ("]" * 5000) + "}"
    assert normalize("signoz", line, NOW) is None
    line = json.dumps(
        {
            "msg": "::RECEIVED-REQUEST::",
            "http.route": "/api/v1/dashboards",
            "http.response.status_code": float("inf"),
        }
    )
    assert normalize("signoz", line, NOW)["status_code"] is None


def test_auxiliary_fields_cannot_make_an_unuploadable_batch():
    ctx = {
        "ip": "fe80::1%" + ("a" * 10000),
        "repository": "a/" + ("b" * 10000),
        "commit": "a" * 40,
    }
    e = normalize(
        "coolify", "production.INFO: webhook.deployment.queued " + json.dumps(ctx), NOW
    )
    assert e["peer_ip"] is None and "repository" not in e
    assert len(json.dumps(e)) < 2000
