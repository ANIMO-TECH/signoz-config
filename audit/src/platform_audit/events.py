"""Allowlist normalizers. Never copy arbitrary headers, URLs, bodies or errors."""

import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

MAX_LINE = 65536
PLATFORMS = {"jobscheduler", "coolify", "signoz"}
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
READ_ROUTES = re.compile(
    r"^/(?:api/v\d+/(?:query_range|health|version)|openplatform/v1/health|_health|health)(?:/|$)"
)
ID = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")
NATIVE = re.compile(
    r"\b((?:api|ui|webhook|auth|operation)\.[a-z0-9_.-]{1,100})\s+(\{.*)$"
)
ACCESS = re.compile(
    r'(?P<peer>\S+) - "(?P<method>GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) (?P<path>\S+) HTTP/[\d.]+" (?P<status>\d{3})\b'
)


def utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timezone required")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_id(value):
    return (
        str(value)
        if isinstance(value, (str, int))
        and not isinstance(value, bool)
        and ID.fullmatch(str(value))
        else None
    )


def peer_ip(value):
    if not isinstance(value, str) or len(value) > 128:
        return None
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value.split("%", 1)[0]))
    except ValueError:
        pass
    if value.startswith("["):
        value = value[1:].split("]", 1)[0]
    elif value.count(":") == 1:
        value = value.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(value.split("%", 1)[0]))
    except (ValueError, OverflowError):
        return None


def _object(raw):
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError, RecursionError):
        return {}


def _base(platform, now):
    return dict(
        schema_version=1,
        platform=platform,
        observed_at=utc(now),
        actor=None,
        target_environment=None,
        peer_ip=None,
        ip_kind="observed_peer",
        resource={"type": "unknown", "id": None},
        method=None,
        route=None,
        status_code=None,
        outcome="observed",
    )


def _choice(value, allowed):
    return isinstance(value, str) and value in allowed


def _operation(e, obj):
    """The producer contract is still allowlisted, never archived verbatim."""
    if obj.get("platform") != e["platform"] or obj.get("schema_version") != 1:
        return None
    action = obj.get("action")
    if not _choice(
        action,
        {
            "job.create",
            "job.update",
            "job.toggle",
            "job.delete",
            "job.run",
            "job.refresh-health",
            "http.mutation",
        },
    ):
        return None
    e["action"] = action
    e["resource"] = {
        "type": "job" if e["platform"] == "jobscheduler" else "unknown",
        "id": safe_id(obj.get("resource_id")),
    }
    e["peer_ip"] = peer_ip(obj.get("peer_ip"))
    e["ip_kind"] = (
        obj.get("ip_kind")
        if _choice(obj.get("ip_kind"), {"asgi_peer", "socket_peer"})
        else "observed_peer"
    )
    e["method"] = obj.get("method") if _choice(obj.get("method"), METHODS) else None
    route = obj.get("route")
    if (
        isinstance(route, str)
        and len(route) <= 300
        and re.fullmatch(r"/api/v\d+/[A-Za-z0-9_/{}/.-]+", route)
    ):
        e["route"] = route
        if classified := _route(e["platform"], route, e["method"], False):
            e["resource"]["type"] = classified[1]["type"]
    actor_type = obj.get("actor_type")
    if _choice(actor_type, {"platform_user", "api_credential_owner"}) and (
        actor_id := safe_id(obj.get("actor_id"))
    ):
        e["actor"] = {"type": actor_type, "id": actor_id}
    if _choice(obj.get("target_environment"), {"prod", "test"}):
        e["target_environment"] = obj["target_environment"]
    for key in ("operation_id", "execution_id"):
        if value := safe_id(obj.get(key)):
            e[key] = value
    if _choice(obj.get("phase"), {"started", "finished"}):
        e["phase"] = obj["phase"]
    outcomes = {
        "started",
        "applied",
        "saved_schedule_failed",
        "unknown_after_save",
        "failed_or_unknown",
        "rejected",
        "request_completed",
        "deleted",
        "health_checked",
        "already_running",
        "http_succeeded",
        "execution_failed",
        "response_write_failed",
    }
    if _choice(obj.get("outcome"), outcomes):
        e["outcome"] = obj["outcome"]
    for key in ("saved", "scheduled", "enabled"):
        if type(obj.get(key)) is bool:
            e[key] = obj[key]
    for key in ("status_code", "audit_dropped_total"):
        value = obj.get(key)
        if type(value) is int and 0 <= value <= (
            599 if key == "status_code" else 2**63 - 1
        ):
            e[key] = value
    e["changed_fields"] = _changed_fields(obj.get("changed_fields"))
    return e


def _changed_fields(value):
    if not isinstance(value, list):
        return []
    return [
        x
        for x in value[:64]
        if isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_]{1,80}", x)
    ]


def _source_time(line, obj, envelope):
    value = envelope or obj.get("timestamp") or obj.get("time") or obj.get("StartUTC")
    if not value:
        m = re.match(r"^\[?(\d{4}-\d\d-\d\d[T ][\d:.]+(?:Z|[+-]\d\d:\d\d)?)", line)
        value = m[1] if m else None
    if not isinstance(value, str) or len(value) > 48:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (
            {"value": utc(parsed), "timezone_known": True}
            if parsed.tzinfo
            else {"value": parsed.isoformat(), "timezone_known": False}
        )
    except (ValueError, OverflowError):
        return None


def _route(platform, path, method, include_reads):
    if not isinstance(path, str) or len(path) > 8192:
        return None
    try:
        path = urlsplit(path).path
    except ValueError:
        return None
    if (
        READ_ROUTES.match(path)
        or path.startswith("/static/")
        or path in ("/", "/favicon.ico")
    ):
        return None
    if method in ("GET", "HEAD", "OPTIONS") and not include_reads:
        return None
    if platform == "jobscheduler":
        m = re.fullmatch(
            r"/(?:openplatform/v1/)?jobs(?:/(\d+))?(?:/(toggle|delete|run|refresh-health|edit|executions|status-history|new))?/?",
            path,
        )
        if not m:
            return None
        ident, action = m.groups()
        if method == "POST":
            action = action or ("update" if ident else "create")
        else:
            action = "inspect"
        route = (
            "/openplatform/v1" if path.startswith("/openplatform") else ""
        ) + "/jobs"
        if ident:
            route += "/{id}"
        if m[2]:
            route += "/" + m[2]
        return "job." + action, {"type": "job", "id": ident}, route
    if platform == "coolify" and path == "/livewire/update":
        return "ui.interaction", {"type": "unknown", "id": None}, path
    # Keep collection/action constants only; never retain arbitrary path segments.
    m = re.fullmatch(
        r"/(?:api/v\d+/)?(dashboards|rules|channels|users|roles|applications|services|servers|deployments|deploy)(?:/([^/]+))?(?:/(start|stop|restart|cancel|lock|envs|rollback))?/?",
        path,
    )
    if not m:
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            return "http.mutation", {"type": "unknown", "id": None}, "/[unmapped]"
        if platform == "signoz" and method is None and path.startswith("/api/"):
            return (
                "platform.request",
                {"type": "unknown", "id": None},
                "/api/[unmapped]",
            )
        return None
    collection, ident, suffix = m.groups()
    singular = {
        "dashboards": "dashboard",
        "rules": "rule",
        "channels": "channel",
        "users": "user",
        "roles": "role",
        "applications": "application",
        "services": "service",
        "servers": "server",
        "deployments": "deployment",
        "deploy": "deployment",
    }[collection]
    verb = {
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
    }.get(method, "request")
    if collection == "deploy":
        verb = "trigger"
    if suffix:
        verb = suffix
    route = ("/api/v1/" if path.startswith("/api/v") else "/") + collection
    if ident:
        route += "/{id}"
    if suffix:
        route += "/" + suffix
    return singular + "." + verb, {"type": singular, "id": safe_id(ident)}, route


def normalize(platform: str, line: str, now: datetime, include_reads=False):
    if platform not in PLATFORMS:
        raise ValueError("unsupported platform")
    if not isinstance(line, str) or len(line.encode("utf-8")) > MAX_LINE:
        return None
    obj = _object(line)
    envelope = None
    if isinstance(obj.get("log"), str):
        envelope = obj.get("time")
        line = obj["log"]  # Docker JSON envelope; envelope contents are never archived.
        obj = _object(line)
    e = _base(platform, now)
    e["source_time"] = _source_time(line, obj, envelope)
    if not obj and "platform.operation" in line:
        start = line.find("{")
        obj = _object(line[start:]) if start >= 0 else {}
        # Some slog handlers prefix the message before the JSON fields.
        if obj and "msg" not in obj:
            obj["msg"] = "platform.operation"
    if obj.get("msg") == "platform.operation":
        return _operation(e, obj)
    native = NATIVE.search(line) if platform == "coolify" else None
    if native:
        try:
            context, _ = json.JSONDecoder().raw_decode(native[2])
        except (ValueError, RecursionError):
            return None
        if not isinstance(context, dict):
            return None
        e["action"] = native[1]
        e["peer_ip"] = peer_ip(context.get("ip"))
        if context.get("ip_kind") == "socket_peer":
            e["ip_kind"] = "socket_peer"
        user = safe_id(context.get("user_id"))
        token = safe_id(context.get("token_id"))
        if token:
            e["actor"] = {"type": "api_credential", "id": token, "owner_id": user}
        elif user:
            e["actor"] = {"type": "platform_user", "id": user}
        for kind in ("application", "service", "server", "database"):
            if ident := safe_id(context.get(kind + "_uuid")):
                e["resource"] = {"type": kind, "id": ident}
                break
        if ident := safe_id(context.get("deployment_uuid")):
            e["deployment_id"] = ident
        if ident := safe_id(context.get("resource_id")):
            e["resource"] = {
                "type": safe_id(context.get("resource_type")) or "unknown",
                "id": ident,
            }
        if ident := safe_id(context.get("operation_id")):
            e["operation_id"] = ident
        for key in ("component", "operation"):
            value = context.get(key)
            if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.]{1,160}", value):
                e[key] = value
        e["changed_fields"] = _changed_fields(context.get("changed_fields"))
        number = context.get("pull_request_id")
        if type(number) is int and 0 < number < 2**31:
            e["pull_request_id"] = number
        commit = context.get("commit")
        repository = context.get("repository")
        if isinstance(commit, str) and re.fullmatch(r"[a-f0-9]{40}", commit):
            e["commit"] = commit
        if isinstance(repository, str) and re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository
        ):
            e["repository"] = repository
        e["outcome"] = (
            "accepted"
            if e["action"].endswith((".triggered", ".queued"))
            else "native_event"
        )
        if _choice(
            context.get("outcome"),
            {
                "attempted",
                "handler_returned",
                "persisted",
                "transaction_pending",
                "queued",
                "commit_resolved",
                "status_changed",
                "accepted",
            },
        ):
            e["outcome"] = context["outcome"]
        return e
    # SigNoz may have a timestamp/logger prefix before its JSON fields.
    if not obj and "::RECEIVED-REQUEST::" in line:
        start = line.find("{")
        obj = _object(line[start:]) if start >= 0 else {}
    if obj and (
        obj.get("msg") == "::RECEIVED-REQUEST::"
        or "::RECEIVED-REQUEST::" in line
        and "http.route" in obj
    ):
        path = obj.get("http.route")
        method = obj.get("http.request.method") or obj.get("http.method")
        status = obj.get("http.response.status_code")
        peer = obj.get("client.address")
    elif obj and "RequestMethod" in obj and "RequestPath" in obj:
        path = obj.get("RequestPath")
        method = obj.get("RequestMethod")
        status = obj.get("DownstreamStatus")
        peer = obj.get("ClientHost") or obj.get("ClientAddr")
    elif match := ACCESS.search(line):
        path = match["path"]
        method = match["method"]
        status = match["status"]
        peer = match["peer"]
    else:
        return None
    method = method if isinstance(method, str) and method in METHODS else None
    classified = _route(platform, path, method, include_reads)
    if not classified:
        return None
    e["action"], e["resource"], e["route"] = classified
    e["method"] = method
    e["peer_ip"] = peer_ip(peer)
    try:
        code = int(status)
    except (ValueError, TypeError, OverflowError):
        code = 0
    e["status_code"] = code if 100 <= code <= 599 else None
    e["outcome"] = (
        "rejected"
        if 400 <= code <= 599
        else "request_completed"
        if 200 <= code <= 399
        else "observed"
    )
    return e
