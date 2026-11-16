"""Normalize a public replay dataset into the lab's ECS-shaped NDJSON.

This module does not claim detection results. It maps common OTRF/Mordor-style
Sysmon and Windows Security fields into the subset the Sigma rules consume, so a
small public sample can be replayed through the same ingest and detect path.

Example:
    python -m pipeline.replay --source path/to/otrf.json --file windows --label malicious
    python -m pipeline.ingest --reset
    python -m pipeline.detect --hours 24 --end 2026-11-11T12:30:00Z
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline.common import LAB_LOGS_DIR, ensure_dir

CHANNEL_DATASET = {
    "microsoft-windows-sysmon/operational": "windows.sysmon_operational",
    "security": "windows.security",
    "system": "windows.system",
}


def _lookup(raw: dict[str, Any], event_data: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = raw.get(name)
        if value in (None, ""):
            value = event_data.get(name)
        if value not in (None, ""):
            return value
    return None


def _timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, dict):
        value = value.get("SystemTime") or value.get("systemTime")
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return None


def _basename(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value.replace("/", "\\").split("\\")[-1]


def _first_ip(value: Any) -> str | None:
    if isinstance(value, list):
        return str(value[0]) if value else None
    if isinstance(value, str):
        return value.split(",")[0].strip() or None
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(str(value), 10)
    except (TypeError, ValueError):
        return None


def infer_file(raw: dict[str, Any], event_data: dict[str, Any]) -> str:
    if raw.get("eventSource") or raw.get("eventName"):
        return "cloud"
    channel = str(_lookup(raw, event_data, "Channel", "channel") or "").lower()
    image = str(_lookup(raw, event_data, "Image", "ProcessPath", "NewProcessName") or "")
    if "sysmon" in channel or channel == "security" or channel == "system" or "windows" in image.lower():
        return "windows"
    if "linux" in channel or "audit" in channel:
        return "linux"
    if "aws" in channel or "cloudtrail" in channel:
        return "cloud"
    if "nginx" in channel or "http" in channel:
        return "web"
    if "zeek" in channel or "flow" in channel:
        return "network"
    return "windows"


def normalize_cloudtrail(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Map a CloudTrail record to the ECS subset used by the cloud rules."""
    timestamp = _timestamp(raw.get("eventTime") or raw.get("@timestamp"))
    if timestamp is None:
        return None
    identity = raw.get("userIdentity") or {}
    identity_type = str(identity.get("type") or "")
    name = identity.get("userName")
    if not name and identity_type.lower() == "root":
        name = "root"
    if not name and identity.get("arn"):
        name = str(identity.get("arn")).split("/")[-1]
    if not name:
        name = identity.get("principalId")
    event_name = str(raw.get("eventName") or "")
    source = str(raw.get("eventSource") or "")
    account = raw.get("recipientAccountId") or identity.get("accountId")
    outcome = "failure" if raw.get("errorCode") else "success"
    category = "authentication" if event_name == "ConsoleLogin" else (
        "iam" if source == "iam.amazonaws.com" else "configuration"
    )

    event: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {
            "kind": "event",
            "module": "aws",
            "dataset": "aws.cloudtrail",
            "category": [category],
            "type": ["info"],
            "action": event_name,
            "code": event_name,
            "outcome": outcome,
            "id": raw.get("eventID"),
        },
        "cloud": {
            "provider": "aws",
            "service": {"name": source},
            "region": raw.get("awsRegion"),
            "account": {"id": str(account)} if account else None,
        },
    }
    if name or identity.get("principalId"):
        event["user"] = {}
        if name:
            event["user"]["name"] = str(name)
        if identity.get("principalId"):
            event["user"]["id"] = str(identity.get("principalId"))
    if raw.get("sourceIPAddress"):
        try:
            ipaddress.ip_address(str(raw.get("sourceIPAddress")))
            event["source"] = {"ip": str(raw.get("sourceIPAddress"))}
        except ValueError:
            # CloudTrail service principals use a hostname here, not an IP.
            pass
    if account:
        event["host"] = {"name": "aws-" + str(account)}
    event["message"] = event_name + (" via " + source if source else "")
    event["cloud"] = {key: value for key, value in event["cloud"].items() if value not in (None, "")}
    event["event"] = {key: value for key, value in event["event"].items() if value not in (None, "")}
    return event


AUDIT_RECORD = re.compile(r"^type=(?P<type>\w+)\s+msg=audit\((?P<id>[^)]+)\)\s*:\s*(?P<body>.*)$")
AUDIT_FIELD = re.compile(r"(?P<key>[A-Za-z0-9_]+)=(?P<value>\"[^\"]*\"|'[^']*'|[^\s]+)")
KV_FIELD = re.compile(r"(?P<key>[A-Za-z0-9_.-]+)=(?P<value>\"[^\"]*\"|'[^']*'|\S+)")
NGINX_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<proto>[^"]+))?" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
AUTH_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:\[]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)


def _strip(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _audit_timestamp(identifier: str) -> str | None:
    stamp = identifier.rsplit(":", 1)[0].strip()
    if "/" in stamp:
        for fmt in ("%m/%d/%Y %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S"):
            try:
                parsed = datetime.strptime(stamp, fmt).replace(tzinfo=timezone.utc)
                return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")
            except ValueError:
                continue
        return None
    try:
        seconds = float(stamp)
    except ValueError:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _audit_fields(body: str) -> dict[str, str]:
    return {match.group("key"): _strip(match.group("value")) for match in AUDIT_FIELD.finditer(body)}


def _decode_hex(value: str) -> str | None:
    text = value.strip()
    if len(text) < 4 or len(text) % 2 or re.fullmatch(r"[0-9a-fA-F]+", text) is None:
        return None
    try:
        return bytes.fromhex(text).decode("utf-8", "replace").replace("\x00", " ").strip()
    except ValueError:
        return None


def load_auditd(text: str) -> list[dict[str, Any]]:
    """Group `type=... msg=audit(...)` records by audit event id.

    Auditd writes one syscall as several records (SYSCALL, EXECVE, PATH, CWD,
    PROCTITLE). They share the `timestamp:serial` identifier and must be merged
    before mapping to ECS.
    """
    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = AUDIT_RECORD.match(line)
        if match is None:
            continue
        identifier = match.group("id")
        if identifier not in groups:
            groups[identifier] = {
                "id": identifier,
                "timestamp": _audit_timestamp(identifier),
                "records": [],
            }
            order.append(identifier)
        groups[identifier]["records"].append(
            {"type": match.group("type"), "fields": _audit_fields(match.group("body"))}
        )
    return [groups[identifier] for identifier in order if groups[identifier]["timestamp"]]


def _audit_user(fields: dict[str, str]) -> str | None:
    for key in ("acct", "auid", "uid", "euid"):
        value = fields.get(key)
        if not value or value in {"unset", "4294967295", "-"}:
            continue
        if not str(value).isdigit():
            return str(value)
    uid = fields.get("uid")
    if str(uid) == "0":
        return "root"
    return str(uid) if uid else None


def normalize_auditd(group: dict[str, Any]) -> dict[str, Any] | None:
    """Map one grouped auditd record set to the lab's ECS subset."""
    records: list[dict[str, Any]] = group.get("records", [])
    syscall = next((record for record in records if record["type"] == "SYSCALL"), None)
    fields: dict[str, str] = syscall["fields"] if syscall else {}
    args: list[str] = []
    proctitle = ""
    paths: list[dict[str, str]] = []
    cwd = ""
    auth_fields: dict[str, str] = {}
    for record in records:
        kind = record["type"]
        item = record["fields"]
        if kind == "EXECVE":
            indexed = sorted(
                ((key, value) for key, value in item.items() if re.fullmatch(r"a\d+", key)),
                key=lambda pair: int(pair[0][1:]),
            )
            for _, value in indexed:
                args.append(value if len(value) < 4 or not re.fullmatch(r"[0-9a-fA-F]+", value) else (_decode_hex(value) or value))
        elif kind == "PROCTITLE" and item.get("proctitle"):
            proctitle = _decode_hex(item["proctitle"]) or item["proctitle"]
        elif kind == "PATH":
            paths.append(item)
        elif kind == "CWD":
            cwd = item.get("cwd", "")
        elif kind.startswith("USER_") or kind in {"CRED_ACQ", "CRED_DISP"}:
            auth_fields.update(item)

    timestamp = group.get("timestamp")
    if not timestamp:
        return None

    command = " ".join(part for part in args if part)
    if not command and proctitle:
        command = proctitle
    executable = fields.get("exe") or (args[0] if args else None)
    if not executable and proctitle:
        executable = proctitle.split(" ")[0]
    name = fields.get("comm") or _basename(executable)

    target = None
    for path in paths:
        if path.get("nametype", "").upper() == "PARENT":
            continue
        if path.get("name"):
            target = path["name"]
            break
    if not target and paths:
        target = paths[0].get("name")
    if target and not str(target).startswith("/") and cwd:
        target = str(cwd).rstrip("/") + "/" + str(target)

    action = "auditd"
    category = "process"
    outcome = None
    if syscall is not None:
        action = "execve" if str(fields.get("syscall")) == "59" or executable else "auditd"
        success = fields.get("success")
        if success in {"yes", "no"}:
            outcome = "success" if success == "yes" else "failure"
    elif auth_fields:
        action = "ssh_auth"
        category = "authentication"
        res = str(auth_fields.get("res") or auth_fields.get("result") or "").lower()
        if res:
            outcome = "success" if res == "success" else "failure"
    elif target:
        action = "file_change"
        category = "file"

    if action == "ssh_auth":
        user = auth_fields.get("acct") or auth_fields.get("auid")
        address = auth_fields.get("addr")
    else:
        user = _audit_user(fields)
        address = fields.get("addr")

    event: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {
            "kind": "event",
            "module": "auditd",
            "dataset": "linux.auditd",
            "category": [category],
            "type": ["start"] if action == "execve" else ["info"],
            "action": action,
        },
        "host": {"name": fields.get("node") or "linux-audit"},
    }
    if outcome:
        event["event"]["outcome"] = outcome
    if user:
        event["user"] = {"name": str(user)}
    if executable:
        event.setdefault("process", {})["executable"] = str(executable)
        event["process"]["name"] = name
    if command:
        event.setdefault("process", {})["command_line"] = command
    if fields.get("pid"):
        event.setdefault("process", {})["pid"] = _as_int(fields["pid"])
    if fields.get("ppid"):
        event.setdefault("process", {}).setdefault("parent", {})["pid"] = _as_int(fields["ppid"])
    if target:
        event["file"] = {"path": str(target)}
    if address:
        try:
            ipaddress.ip_address(str(address))
            event["source"] = {"ip": str(address)}
        except ValueError:
            pass

    message = command or (str(target) if target else "")
    if message:
        event["message"] = message
    event = {key: value for key, value in event.items() if value not in ({}, None)}
    return event


def _nginx_timestamp(value: str) -> str | None:
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            parsed = datetime.strptime(value.strip(), fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        except ValueError:
            continue
    return None


def _split_url(value: str) -> tuple[str, str | None]:
    path, _, query = value.partition("?")
    return path or "/", query or None


def normalize_nginx(line: str) -> dict[str, Any] | None:
    """Map a combined-format nginx line or a key=value nginx record."""
    line = line.strip()
    if not line:
        return None
    if "time_local=" in line:
        fields = {match.group("key"): _strip(match.group("value")) for match in KV_FIELD.finditer(line)}
        timestamp = _nginx_timestamp(fields.get("time_local", ""))
        if timestamp is None:
            return None
        path, query = _split_url(fields.get("uri_path") or "/")
        if fields.get("uri_query") not in (None, "", "-"):
            query = fields["uri_query"]
        status = _as_int(fields.get("status"))
        size = _as_int(fields.get("bytes_out"))
        method = fields.get("http_method")
        ip = fields.get("src_ip") or fields.get("src")
        user = fields.get("user")
        agent = fields.get("http_user_agent")
        host = fields.get("server") or fields.get("site") or "web-01"
    else:
        match = NGINX_LINE.match(line)
        if match is None:
            return None
        timestamp = _nginx_timestamp(match.group("ts"))
        if timestamp is None:
            return None
        path, query = _split_url(match.group("path"))
        status = _as_int(match.group("status"))
        size = _as_int(match.group("bytes"))
        method = match.group("method")
        ip = match.group("ip")
        user = match.group("user")
        agent = match.group("ua")
        host = "web-01"

    event: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {
            "kind": "event",
            "module": "nginx",
            "dataset": "nginx.access",
            "category": ["web"],
            "type": ["access"],
            "action": "web_request",
        },
        "host": {"name": str(host)},
        "url": {"path": str(path)},
        "http": {"request": {"method": str(method or "")}},
    }
    if query:
        event["url"]["query"] = str(query)
    if status is not None:
        event["http"].setdefault("response", {})["status_code"] = status
    if size is not None:
        event["http"].setdefault("response", {})["bytes"] = size
    if ip:
        try:
            ipaddress.ip_address(str(ip))
            event["source"] = {"ip": str(ip)}
        except ValueError:
            pass
    if user and user != "-":
        event["user"] = {"name": str(user)}
    if agent and agent != "-":
        event["user_agent"] = {"original": str(agent)}
    event["message"] = f"{method or 'GET'} {path}" + (f"?{query}" if query else "")
    return event


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"t", "true", "1", "yes"}:
            return True
        if lowered in {"f", "false", "0", "no"}:
            return False
    return None


def _direction(source_ip: str | None, dest_ip: str | None, local_orig: Any, local_resp: Any) -> str | None:
    orig = _as_bool(local_orig)
    resp = _as_bool(local_resp)
    if orig is True and resp is False:
        return "outbound"
    if orig is False and resp is True:
        return "inbound"
    if orig is True and resp is True:
        return "internal"
    if orig is False and resp is False:
        return "external"
    try:
        src_private = ipaddress.ip_address(str(source_ip)).is_private if source_ip else None
        dst_private = ipaddress.ip_address(str(dest_ip)).is_private if dest_ip else None
    except ValueError:
        return None
    if src_private and dst_private is False:
        return "outbound"
    if src_private is False and dst_private:
        return "inbound"
    if src_private and dst_private:
        return "internal"
    return None


def normalize_zeek(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Map a Zeek conn record (JSON or tab-separated) to an ECS network flow."""
    timestamp = _timestamp(raw.get("ts"))
    if timestamp is None:
        return None
    source_ip = raw.get("id.orig_h")
    dest_ip = raw.get("id.resp_h")
    orig_bytes = _as_int(raw.get("orig_bytes"))
    resp_bytes = _as_int(raw.get("resp_bytes"))
    total = (orig_bytes or 0) + (resp_bytes or 0) if orig_bytes is not None or resp_bytes is not None else None
    event: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {
            "kind": "event",
            "module": "zeek",
            "dataset": "zeek.conn",
            "category": ["network"],
            "type": ["connection"],
            "action": "network_flow",
        },
        "host": {"name": "zeek-sensor"},
        "network": {"transport": str(raw.get("proto") or "").lower() or None},
    }
    if source_ip:
        event["source"] = {"ip": str(source_ip)}
    if raw.get("id.orig_p") not in (None, "-"):
        event.setdefault("source", {})["port"] = _as_int(raw.get("id.orig_p"))
    if dest_ip:
        event["destination"] = {"ip": str(dest_ip)}
    if raw.get("id.resp_p") not in (None, "-"):
        event.setdefault("destination", {})["port"] = _as_int(raw.get("id.resp_p"))
    direction = _direction(source_ip, dest_ip, raw.get("local_orig"), raw.get("local_resp"))
    if direction:
        event["network"]["direction"] = direction
    if total is not None:
        event["network"]["bytes"] = total
    event["network"] = {key: value for key, value in event["network"].items() if value not in (None, "")}
    event["message"] = (
        f"{source_ip}:{raw.get('id.orig_p', '-')} -> {dest_ip}:{raw.get('id.resp_p', '-')} "
        f"{raw.get('proto', '')} {total if total is not None else 0} bytes {raw.get('conn_state', '')}"
    ).strip()
    return event


def load_zeek(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    fields: list[str] | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        if line.lstrip().startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                records.append(payload)
        elif fields:
            values = line.split("\t")
            if len(values) == len(fields):
                records.append(dict(zip(fields, values)))
    return records


def normalize_auth(line: str, year: int) -> dict[str, Any] | None:
    """Map a syslog auth line (sshd, sudo, useradd) to ECS."""
    match = AUTH_LINE.match(line.strip())
    if match is None:
        return None
    try:
        parsed = datetime.strptime(f"{year} {match.group('ts')}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    timestamp = parsed.isoformat(timespec="seconds").replace("+00:00", "Z")
    message = match.group("msg")
    host = match.group("host")
    action = "auth"
    outcome = None
    user = None
    address = None
    command = None

    accepted = re.search(r"Accepted (?:password|publickey) for (\S+) from (\S+)", message)
    failed = re.search(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)", message)
    invalid = re.search(r"Invalid user (\S+) from (\S+)", message)
    session = re.search(r"session opened for user (\S+)", message)
    sudo = re.search(r"USER=(\S+).*?COMMAND=(.*)$", message)
    new_user = re.search(r"new user: name=([^,]+)", message)

    if accepted:
        action, outcome, user, address = "ssh_auth", "success", accepted.group(1), accepted.group(2)
    elif failed:
        action, outcome, user, address = "ssh_auth", "failure", failed.group(1), failed.group(2)
    elif invalid:
        action, outcome, user, address = "ssh_auth", "failure", invalid.group(1), invalid.group(2)
    elif session:
        action, outcome, user = "session", "success", session.group(1)
    elif sudo and "sudo" in match.group("proc"):
        action, user, command = "sudo", sudo.group(1), sudo.group(2).strip()
    elif new_user:
        action, user = "user_created", new_user.group(1).strip()

    category = "authentication" if action in {"ssh_auth", "session"} else "iam"
    event: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {
            "kind": "event",
            "module": "system",
            "dataset": "linux.auth",
            "category": [category],
            "type": ["start"] if action == "session" else ["info"],
            "action": action,
        },
        "host": {"name": host},
        "message": message,
    }
    if outcome:
        event["event"]["outcome"] = outcome
    if user:
        event["user"] = {"name": user}
    if address:
        try:
            ipaddress.ip_address(address)
            event["source"] = {"ip": address}
        except ValueError:
            pass
    if command:
        event["process"] = {"command_line": command, "name": command.split(" ")[0]}
    return event


def load_windows_xml(text: str) -> list[str]:
    """Return complete <Event> blocks, including blocks wrapped across lines."""
    return re.findall(r"<Event\b.*?</Event>", text, re.S)


def normalize_windows_xml(block: str) -> dict[str, Any] | None:
    """Map a Windows Event Log XML record to the same shape as OTRF JSON."""
    try:
        root = ET.fromstring(block)
    except ET.ParseError:
        return None
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", namespace)
    if system is None:
        return None
    event_id = (system.findtext("e:EventID", default="", namespaces=namespace) or "").strip()
    channel = system.findtext("e:Channel", default="", namespaces=namespace) or ""
    computer = system.findtext("e:Computer", default="", namespaces=namespace) or ""
    provider = system.find("e:Provider", namespace)
    time_node = system.find("e:TimeCreated", namespace)
    timestamp = time_node.get("SystemTime") if time_node is not None else None
    data: dict[str, str] = {}
    for node in root.findall("e:EventData/e:Data", namespace):
        name = node.get("Name")
        if name:
            data[name] = node.text or ""
    raw: dict[str, Any] = {
        "EventID": event_id,
        "Channel": channel,
        "Computer": computer,
        "TimeCreated": timestamp,
        "EventData": data,
    }
    if provider is not None:
        raw["ProviderName"] = provider.get("Name")
    return normalize_event(raw)


def _detect_format(text: str, first_line: str) -> str:
    if first_line.startswith("<Event"):
        return "winxml"
    if first_line.startswith("type="):
        return "auditd"
    if "time_local=" in first_line:
        return "nginx"
    if first_line.startswith("#") and "#fields" in text:
        return "zeek"
    if first_line.startswith("{"):
        try:
            payload = json.loads(first_line)
        except json.JSONDecodeError:
            return "otrf"
        if isinstance(payload, dict) and "id.orig_h" in payload:
            return "zeek"
        return "otrf"
    if NGINX_LINE.match(first_line):
        return "nginx"
    if AUTH_LINE.match(first_line):
        return "auth"
    return "otrf"


def load_text_events(text: str, fmt: str, year: int) -> list[dict[str, Any]]:
    if fmt == "winxml":
        return [event for block in load_windows_xml(text) if (event := normalize_windows_xml(block))]
    if fmt == "auditd":
        return [event for group in load_auditd(text) if (event := normalize_auditd(group))]
    if fmt == "nginx":
        return [event for line in text.splitlines() if (event := normalize_nginx(line))]
    if fmt == "zeek":
        return [event for raw in load_zeek(text) if (event := normalize_zeek(raw))]
    if fmt == "auth":
        return [event for line in text.splitlines() if (event := normalize_auth(line, year))]
    return [event for raw in load_events_text(text) if (event := normalize_event(raw))]


def load_events_text(text: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("events"), list):
        return payload["events"]
    if isinstance(payload, dict):
        return [payload]
    return []


def normalize_event(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Map one OTRF/Mordor-style event to the lab's ECS subset.

    Returns None when the event has no usable timestamp. The original event is
    not copied into the output; only the fields needed for detection and triage
    are retained.
    """
    raw = dict(raw or {})
    if raw.get("eventSource") or (raw.get("eventName") and raw.get("userIdentity")):
        return normalize_cloudtrail(raw)
    event_data = raw.get("EventData") or raw.get("event_data") or {}
    if isinstance(event_data, str):
        event_data = {}
    if not isinstance(event_data, dict):
        event_data = {}

    timestamp = _timestamp(
        _lookup(raw, event_data, "@timestamp", "timestamp", "UtcTime", "TimeCreated", "TimeGenerated")
    )
    if timestamp is None:
        return None

    channel = str(_lookup(raw, event_data, "Channel", "channel") or "")
    event_id = _lookup(raw, event_data, "EventID", "event_id", "EventId")
    event_id = str(event_id) if event_id is not None else None
    host = _lookup(raw, event_data, "Computer", "Hostname", "host.name", "host")
    if isinstance(host, dict):
        host = host.get("name")

    image = _lookup(
        raw,
        event_data,
        "Image",
        "SourceImage",
        "ProcessPath",
        "NewProcessName",
        "Application",
        "process.executable",
    )
    command = _lookup(raw, event_data, "CommandLine", "ProcessCommandLine", "command_line", "process.command_line")
    parent_image = _lookup(raw, event_data, "ParentImage", "ParentProcessName", "process.parent.executable")
    parent_command = _lookup(raw, event_data, "ParentCommandLine", "process.parent.command_line")
    user = _lookup(raw, event_data, "User", "SubjectUserName", "TargetUserName", "user.name")
    pid = _lookup(raw, event_data, "ProcessId", "SourceProcessId", "NewProcessId", "process.pid")

    category = "process"
    action = "process_start"
    if event_id in {"3", "5156"}:
        category, action = "network", "network_connection"
    elif event_id in {"8"}:
        category, action = "process", "remote_thread"
    elif event_id in {"10"}:
        category, action = "process", "process_access"
    elif event_id in {"11"}:
        category, action = "file", "file_create"
    elif event_id in {"12", "13", "14"}:
        category, action = "registry", "registry_change"
    elif event_id in {"22"}:
        category, action = "network", "dns_query"
    elif event_id in {"4688"}:
        category, action = "process", "process_start"

    event: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {
            "kind": "event",
            "module": "otrf",
            "dataset": CHANNEL_DATASET.get(channel.lower(), "otrf.replay"),
            "category": category,
            "type": ["start"] if action == "process_start" else ["info"],
            "action": action,
            "code": event_id,
        },
        "host": {"name": str(host)} if host else {},
        "user": {"name": str(user)} if user else {},
        "process": {},
        "winlog": {
            "channel": channel,
            "event_id": event_id,
            "computer_name": str(host) if host else None,
        },
    }
    winlog_data: dict[str, str] = {}
    for key in (
        "ServiceName",
        "ImagePath",
        "TargetImage",
        "GrantedAccess",
        "ShareName",
        "TicketEncryptionType",
        "Details",
        "TargetFilename",
        "TargetObject",
        "SourceImage",
        "SourceProcessId",
        "TargetProcessId",
        "NewThreadId",
        "StartAddress",
        "StartModule",
        "StartFunction",
        "Hashes",
        "Signed",
        "Signature",
        "QueryName",
        "ScriptBlockText",
        "CommandLine",
        "ParentCommandLine",
        "Image",
        "ParentImage",
        "User",
        "TargetUserName",
        "SubjectUserName",
        "DestinationPort",
        "SourceIp",
        "DestinationIp",
    ):
        value = _lookup(raw, event_data, key)
        if value not in (None, ""):
            winlog_data[key] = str(value)
    if winlog_data:
        event["winlog"]["event_data"] = winlog_data
    provider = _lookup(raw, event_data, "SourceName", "ProviderName", "winlog.provider_name")
    if provider:
        event["winlog"]["provider_name"] = str(provider)
    message = _lookup(raw, event_data, "Message", "message")
    if message:
        event["message"] = str(message)
    if image:
        event["process"]["executable"] = str(image)
        event["process"]["executable.caseless"] = str(image).lower()
        event["process"]["name"] = _basename(image)
    if command:
        event["process"]["command_line"] = str(command)
    if parent_image:
        event["process"]["parent"] = {
            "executable": str(parent_image),
            "executable.caseless": str(parent_image).lower(),
            "name": _basename(parent_image),
        }
    if parent_command:
        event["process"].setdefault("parent", {})["command_line"] = str(parent_command)
    if pid is not None:
        event["process"]["pid"] = _as_int(pid)

    source_ip = _first_ip(_lookup(raw, event_data, "SourceIp", "SourceAddress", "SourceIP", "source.ip", "src_ip"))
    dest_ip = _first_ip(
        _lookup(raw, event_data, "DestinationIp", "DestAddress", "DestinationIP", "destination.ip", "dest_ip")
    )
    dest_port = _as_int(
        _lookup(raw, event_data, "DestinationPort", "DestPort", "destination.port", "dest_port")
    )
    if source_ip or dest_ip:
        event["source"] = {"ip": source_ip} if source_ip else {}
        event["destination"] = {"ip": dest_ip, "port": dest_port} if dest_ip or dest_port else {}
        event["network"] = {"transport": _lookup(raw, event_data, "Protocol", "network.transport")}
    target_file = _lookup(raw, event_data, "TargetFilename", "file.path")
    if target_file:
        event["file"] = {"path": str(target_file)}
    registry_path = _lookup(raw, event_data, "TargetObject", "registry.path")
    if registry_path:
        event["registry"] = {"path": str(registry_path)}
    query = _lookup(raw, event_data, "QueryName", "dns.question.name")
    if query:
        event["dns"] = {"question": {"name": str(query)}}
    script = _lookup(raw, event_data, "ScriptBlockText", "powershell.file.script_block_text")
    if script:
        event["powershell"] = {"file": {"script_block_text": str(script)}}

    # Drop empty nested objects so the index template stays clean.
    event = {key: value for key, value in event.items() if value not in ({}, None)}
    if "process" in event and not event["process"]:
        del event["process"]
    if "winlog" in event:
        event["winlog"] = {key: value for key, value in event["winlog"].items() if value not in (None, "")}
    return event


def load_events(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".ndjson", ".jsonl"}:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return load_events_text(text)


def replay(
    source: Path,
    out_dir: Path,
    file_name: str | None,
    label: str,
    limit: int | None,
    format_name: str = "auto",
    append: bool = False,
    year: int = 2026,
) -> dict[str, Any]:
    text = source.read_text(encoding="utf-8")
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if format_name == "auto":
        format_name = _detect_format(text, first_line)

    normalized = load_text_events(text, format_name, year)
    if limit:
        normalized = normalized[:limit]
    if not normalized:
        raise SystemExit("No events had a usable timestamp; nothing was written.")
    normalized.sort(key=lambda event: str(event.get("@timestamp", "")))

    if file_name is None:
        file_name = {
            "auditd": "linux",
            "auth": "linux",
            "nginx": "web",
            "zeek": "network",
            "winxml": "windows",
        }.get(format_name)
    if file_name is None:
        first_raw = load_events_text(text)[:1]
        data = (first_raw[0].get("EventData") or first_raw[0].get("event_data") or {}) if first_raw else {}
        file_name = infer_file(first_raw[0] if first_raw else {}, data if isinstance(data, dict) else {})

    ensure_dir(out_dir)
    target = out_dir / f"{file_name}.ndjson"
    existing = 0
    if append and target.exists():
        existing = sum(1 for line in target.read_text(encoding="utf-8").splitlines() if line.strip())
        with target.open("a", encoding="utf-8") as handle:
            handle.write("".join(json.dumps(event, sort_keys=False) + "\n" for event in normalized))
    else:
        target.write_text("".join(json.dumps(event, sort_keys=False) + "\n" for event in normalized), encoding="utf-8")

    manifest = {
        "source": str(source),
        "format": format_name,
        "file": str(target),
        "index": file_name,
        "label": label,
        "events": len(normalized),
        "total_events": existing + len(normalized) if append else len(normalized),
        "appended": append,
        "skipped": 0 if format_name != "otrf" else max(0, len(load_events_text(text)) - len(normalized)),
        "first": normalized[0]["@timestamp"],
        "last": normalized[-1]["@timestamp"],
        "note": "Normalized replay data; detection results require pipeline.ingest and pipeline.detect.",
    }
    (out_dir / "replay-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize a public replay dataset for the lab")
    parser.add_argument("--source", required=True, help="OTRF/Mordor JSON, auditd, nginx, auth, or Zeek log")
    parser.add_argument("--out", default=str(LAB_LOGS_DIR), help="Output directory for lab NDJSON")
    parser.add_argument("--file", choices=("windows", "linux", "web", "cloud", "network"), help="Target index family")
    parser.add_argument(
        "--format",
        choices=("auto", "otrf", "auditd", "nginx", "zeek", "auth", "winxml"),
        default="auto",
        help="Input parser (default: detect from the first line)",
    )
    parser.add_argument("--label", choices=("malicious", "benign", "unlabeled"), default="unlabeled")
    parser.add_argument("--append", action="store_true", help="Append to an existing index file")
    parser.add_argument("--year", type=int, default=2026, help="Year for yearless syslog timestamps")
    parser.add_argument("--limit", type=int, help="Only normalize the first N events")
    parser.add_argument("--dry-run", action="store_true", help="Print a sample instead of writing")
    args = parser.parse_args()

    source = Path(args.source)
    if not source.is_file():
        raise SystemExit(f"Replay source not found: {source}")

    if args.dry_run:
        text = source.read_text(encoding="utf-8")
        first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
        fmt = args.format if args.format != "auto" else _detect_format(text, first_line)
        events = load_text_events(text, fmt, args.year)[: args.limit or 1]
        print(json.dumps(events[0], indent=2) if events else "No usable event")
        return

    manifest = replay(
        source,
        Path(args.out),
        args.file,
        args.label,
        args.limit,
        format_name=args.format,
        append=args.append,
        year=args.year,
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
