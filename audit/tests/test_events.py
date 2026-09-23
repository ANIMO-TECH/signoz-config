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


def test_semantic_producer_events_keep_business_outcome_and_no_secrets():
    raw = dict(
        msg="platform.operation",
        schema_version=1,
        platform="jobscheduler",
        action="job.toggle",
        operation_id="operation-1",
        resource_id="23",
        target_environment="test",
        peer_ip="192.0.2.4",
        ip_kind="asgi_peer",
        method="POST",
        phase="finished",
        outcome="saved_schedule_failed",
        saved=True,
        scheduled=False,
        status_code=303,
        changed_fields=["enabled"],
        headers={"Authorization": "secret"},
        password="secret",
    )
    event = normalize("jobscheduler", json.dumps(raw), NOW)
    assert event["outcome"] == "saved_schedule_failed" and event["status_code"] == 303
    raw["scheduled"] = None
    assert normalize("jobscheduler", json.dumps(raw), NOW)["scheduled"] is None
    assert event["actor"] is None and event["resource"]["id"] == "23"
    assert event["target_environment"] == "test" and event["changed_fields"] == [
        "enabled"
    ]
    assert "secret" not in json.dumps(event)
    raw.update(
        platform="signoz",
        action="http.mutation",
        route="/api/v1/dashboards/{id}",
        method="DELETE",
        actor_type="api_credential_owner",
        actor_id="user-1",
    )
    event = normalize("signoz", json.dumps(raw), NOW)
    assert event["actor"] == {"type": "api_credential_owner", "id": "user-1"}
    assert event["resource"] == {"type": "dashboard", "id": "23"}


def test_coolify_semantic_model_and_deployment_events():
    line = "production.INFO: operation.model.updated " + json.dumps(
        dict(
            resource_type="Application",
            resource_id="app-1",
            user_id=17,
            operation_id="operation-1",
            changed_fields=["git_branch"],
            outcome="transaction_pending",
            ip="192.0.2.5",
            ip_kind="socket_peer",
        )
    )
    event = normalize("coolify", line, NOW)
    assert (
        event["outcome"] == "transaction_pending" and event["resource"]["id"] == "app-1"
    )
    assert event["operation_id"] == "operation-1" and event["actor"]["id"] == "17"
    line = "production.INFO: operation.deployment.commit_resolved " + json.dumps(
        dict(
            deployment_uuid="run-1",
            application_uuid="app-1",
            repository="ANIMO-TECH/jobscheduler",
            commit="a" * 40,
            outcome="commit_resolved",
        )
    )
    event = normalize("coolify", line, NOW)
    assert event["commit"] == "a" * 40 and event["deployment_id"] == "run-1"
    assert event["actor"] is None


def test_malformed_new_producer_fields_do_not_stop_collector():
    for field in (
        "action",
        "method",
        "actor_type",
        "phase",
        "outcome",
        "target_environment",
        "ip_kind",
    ):
        for value in ([], {}, None, True):
            raw = dict(
                msg="platform.operation",
                schema_version=1,
                platform="signoz",
                action="http.mutation",
            )
            raw[field] = value
            normalize("signoz", json.dumps(raw), NOW)


def test_signoz_key_revocation_keeps_object_id_without_copying_secret():
    raw = dict(
        msg="platform.operation",
        schema_version=1,
        platform="signoz",
        action="http.mutation",
        method="DELETE",
        route="/api/v1/pats/{id}",
        resource_id="key-record-id",
        token="secret",
        phase="finished",
        outcome="request_completed",
    )
    event = normalize("signoz", json.dumps(raw), NOW)
    assert event["resource"] == {"type": "api_key", "id": "key-record-id"}
    assert "secret" not in json.dumps(event)


def test_uvicorn_ipv6_client_address_does_not_include_the_source_port():
    for port in (8000, 54321):
        line = f'INFO: 2001:db8::1:{port} - "POST /jobs/1/run HTTP/1.1" 303 See Other'
        event = normalize("jobscheduler", line, NOW)
        assert event["peer_ip"] == "2001:db8::1"


def test_invalid_uvicorn_socket_port_does_not_stop_collection():
    for port in ("65536", "²"):
        line = f'INFO: 2001:db8::1:{port} - "POST /jobs/1/run HTTP/1.1" 303 See Other'
        assert normalize("jobscheduler", line, NOW)["peer_ip"] is None
