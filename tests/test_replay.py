"""Tests for the public replay normalizer."""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.replay import (
    load_auditd,
    normalize_auditd,
    normalize_auth,
    normalize_event,
    normalize_nginx,
    normalize_windows_xml,
    normalize_zeek,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sysmon_process_create.json"


def test_normalize_sysmon_process_create() -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))[0]
    event = normalize_event(raw)

    assert event is not None
    assert event["@timestamp"] == "2026-11-11T12:10:40Z"
    assert event["host"]["name"] == "WIN10-LAB"
    assert event["event"]["dataset"] == "windows.sysmon_operational"
    assert event["event"]["action"] == "process_start"
    assert event["winlog"]["event_id"] == "1"
    assert event["process"]["executable.caseless"].endswith("rundll32.exe")
    assert "comsvcs.dll" in event["process"]["command_line"]
    assert event["process"]["parent"]["name"] == "cmd.exe"
    assert event["winlog"]["event_data"]["TargetImage"].endswith("lsass.exe")
    assert event["winlog"]["event_data"]["GrantedAccess"] == "0x1010"


def test_normalize_cloudtrail_create_access_key() -> None:
    event = normalize_event(
        {
            "eventTime": "2020-09-14T00:44:23Z",
            "eventName": "CreateAccessKey",
            "eventSource": "iam.amazonaws.com",
            "awsRegion": "us-east-1",
            "recipientAccountId": "123456789123",
            "eventID": "fd4f1042",
            "sourceIPAddress": "1.2.3.4",
            "userIdentity": {"type": "IAMUser", "userName": "pedro", "principalId": "AIDA"},
        }
    )
    assert event is not None
    assert event["event"]["dataset"] == "aws.cloudtrail"
    assert event["event"]["action"] == "CreateAccessKey"
    assert event["event"]["outcome"] == "success"
    assert event["user"]["name"] == "pedro"
    assert event["cloud"]["provider"] == "aws"
    assert event["cloud"]["service"]["name"] == "iam.amazonaws.com"


def test_normalize_cloudtrail_root_console_login() -> None:
    event = normalize_event(
        {
            "eventTime": "2020-09-14T00:44:23Z",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "recipientAccountId": "123456789123",
            "userIdentity": {"type": "Root", "principalId": "root"},
        }
    )
    assert event is not None
    assert event["user"]["name"] == "root"
    assert event["event"]["action"] == "ConsoleLogin"
    assert event["event"]["outcome"] == "success"


def test_normalize_without_timestamp_is_skipped() -> None:
    assert normalize_event({"Image": "C:\\Windows\\System32\\cmd.exe"}) is None


def test_normalize_sysmon_process_access_and_registry() -> None:
    access = normalize_event(
        {
            "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "WIN10-LAB",
            "UtcTime": "2026-11-11T12:10:40.000Z",
            "SourceImage": "C:\\Tools\\dump.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "SourceProcessId": "1234",
            "TargetProcessId": "640",
        }
    )
    assert access is not None
    assert access["event"]["action"] == "process_access"
    assert access["process"]["executable"].endswith("dump.exe")
    assert access["process"]["pid"] == 1234
    assert access["winlog"]["event_data"]["TargetImage"].endswith("lsass.exe")
    assert access["winlog"]["event_data"]["GrantedAccess"] == "0x1010"

    registry = normalize_event(
        {
            "EventID": 13,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "WIN10-LAB",
            "UtcTime": "2026-11-11T12:10:41.000Z",
            "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "Details": "C:\\Users\\Public\\updater.exe",
        }
    )
    assert registry is not None
    assert registry["event"]["action"] == "registry_change"
    assert registry["registry"]["path"].endswith("Run\\Updater")
    assert registry["winlog"]["event_data"]["Details"].endswith("updater.exe")


def test_auditd_groups_records_into_one_event() -> None:
    text = "\n".join(
        [
            "type=SYSCALL msg=audit(1604996384.965:93777): arch=c000003e syscall=59 success=yes "
            'ppid=29002 pid=2168 auid=1000 uid=1000 comm="dd" exe="/bin/dd" key=(null)',
            "type=EXECVE msg=audit(1604996384.965:93777): argc=4 a0=\"dd\" a1=\"if=/dev/zero\" "
            'a2="bs=1" a3="count=1"',
            "type=CWD msg=audit(1604996384.965:93777): cwd=\"/home/wardog\"",
            "type=PATH msg=audit(1604996384.965:93777): item=0 name=\"/bin/dd\" nametype=NORMAL",
            "type=PATH msg=audit(1604996384.965:93777): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" "
            "nametype=NORMAL",
            "type=PROCTITLE msg=audit(1604996384.965:93777): "
            "proctitle=64640069663D2F6465762F7A65726F0062733D3100636F756E743D31",
        ]
    )
    groups = load_auditd(text)
    assert len(groups) == 1
    event = normalize_auditd(groups[0])
    assert event is not None
    assert event["@timestamp"] == "2020-11-10T08:19:44Z"
    assert event["event"]["dataset"] == "linux.auditd"
    assert event["event"]["action"] == "execve"
    assert event["event"]["outcome"] == "success"
    assert event["process"]["executable"] == "/bin/dd"
    assert event["process"]["name"] == "dd"
    assert event["process"]["command_line"] == "dd if=/dev/zero bs=1 count=1"
    assert event["process"]["pid"] == 2168
    assert event["file"]["path"] == "/bin/dd"
    assert event["user"]["name"] == "1000"


def test_auditd_accepts_month_day_timestamp_and_path_target() -> None:
    text = "\n".join(
        [
            "type=PATH msg=audit(11/20/2025 16:57:48.909:110027): item=1 name=\"authorized_keys\" "
            "nametype=CREATE",
            "type=PATH msg=audit(11/20/2025 16:57:48.909:110027): item=0 name=\"/home/backup/.ssh\" "
            "nametype=PARENT",
            "type=CWD msg=audit(11/20/2025 16:57:48.909:110027): cwd=\"/home/backup\"",
        ]
    )
    event = normalize_auditd(load_auditd(text)[0])
    assert event is not None
    assert event["@timestamp"] == "2025-11-20T16:57:48Z"
    assert event["event"]["action"] == "file_change"
    assert event["file"]["path"] == "/home/backup/authorized_keys"


def test_normalize_nginx_combined_and_key_value() -> None:
    combined = normalize_nginx(
        '89.160.20.156 - - [25/Oct/2016:14:49:33 +0200] "GET /login?id=1 HTTP/1.1" '
        '200 612 "-" "sqlmap/1.5"'
    )
    assert combined is not None
    assert combined["@timestamp"] == "2016-10-25T12:49:33Z"
    assert combined["event"]["action"] == "web_request"
    assert combined["url"]["path"] == "/login"
    assert combined["url"]["query"] == "id=1"
    assert combined["http"]["request"]["method"] == "GET"
    assert combined["http"]["response"]["status_code"] == 200
    assert combined["user_agent"]["original"] == "sqlmap/1.5"

    key_value = normalize_nginx(
        'src_ip="198.51.100.1" time_local="22/Feb/2024:12:34:56 -0500" '
        'http_method="POST" uri_path="/wp-json/bricks/v1/render_element" uri_query="-" status="200"'
    )
    assert key_value is not None
    assert key_value["@timestamp"] == "2024-02-22T17:34:56Z"
    assert key_value["url"]["path"] == "/wp-json/bricks/v1/render_element"
    assert key_value["http"]["request"]["method"] == "POST"


def test_normalize_zeek_connection_flow() -> None:
    event = normalize_zeek(
        {
            "ts": 1547188415.857497,
            "id.orig_h": "192.168.86.167",
            "id.orig_p": 38340,
            "id.resp_h": "175.16.199.1",
            "id.resp_p": 53,
            "proto": "udp",
            "orig_bytes": 75,
            "resp_bytes": 178,
            "local_orig": True,
            "local_resp": False,
            "conn_state": "SF",
        }
    )
    assert event is not None
    assert event["@timestamp"] == "2019-01-11T06:33:35Z"
    assert event["event"]["dataset"] == "zeek.conn"
    assert event["network"]["direction"] == "outbound"
    assert event["network"]["bytes"] == 253
    assert event["destination"]["port"] == 53


def test_normalize_auth_accepted_failed_and_sudo() -> None:
    accepted = normalize_auth(
        "Feb 21 21:54:44 localhost sshd[3402]: Accepted publickey for root from 10.0.2.2 port 63673 ssh2",
        2026,
    )
    assert accepted is not None
    assert accepted["event"]["action"] == "ssh_auth"
    assert accepted["event"]["outcome"] == "success"
    assert accepted["user"]["name"] == "root"
    assert accepted["source"]["ip"] == "10.0.2.2"

    failed = normalize_auth(
        "Feb 22 16:45:20 slave22 sshd[2738]: Failed password for root from 202.196.224.106 port 1786 ssh2",
        2026,
    )
    assert failed is not None
    assert failed["event"]["outcome"] == "failure"

    sudo = normalize_auth(
        "Feb 22 16:45:20 slave22 sudo:  drewr : USER=root ; COMMAND=/bin/rm -rf /var/log",
        2026,
    )
    assert sudo is not None
    assert sudo["event"]["action"] == "sudo"
    assert sudo["user"]["name"] == "root"
    assert sudo["process"]["command_line"] == "/bin/rm -rf /var/log"


def test_normalize_windows_xml_service_creation() -> None:
    block = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='Service Control Manager'/><EventID>7045</EventID>"
        "<TimeCreated SystemTime='2024-03-04T10:11:25.4839860Z'/>"
        "<Channel>System</Channel><Computer>ar-win-dc.attackrange.local</Computer></System>"
        "<EventData><Data Name='ServiceName'>KrbSCM</Data>"
        "<Data Name='ImagePath'>powershell.exe -WindowStyle Hidden</Data>"
        "<Data Name='StartType'>demand start</Data></EventData></Event>"
    )
    event = normalize_windows_xml(block)
    assert event is not None
    assert event["@timestamp"] == "2024-03-04T10:11:25Z"
    assert event["event"]["code"] == "7045"
    assert event["event"]["dataset"] == "windows.system"
    assert event["winlog"]["event_data"]["ServiceName"] == "KrbSCM"
    assert event["winlog"]["event_data"]["ImagePath"].startswith("powershell.exe")
