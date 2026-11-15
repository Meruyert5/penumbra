# Analyst Runbook

How to work the queue this pipeline produces. Treat the alerts as real. That habit is the point.

## 1. Start the shift

```powershell
docker compose up -d
.\.venv\Scripts\python.exe -m pipeline.detect --hours 24
Get-Content alerts\summary.md
```

`alerts/summary.md` is the queue: rule matches grouped by severity, then correlation alerts. Work top-down by severity, not by count.

## 2. Triage order

| Priority | Alert | First question |
|---|---|---|
| 1 | LSASS process access | Which process, which user, and was it signed? |
| 2 | Defender disabled | Who disabled it, and what ran in the next 10 minutes? |
| 3 | Service install from user path | Is the binary signed, and does the service name match an installer? |
| 4 | Encoded PowerShell | What is the decoded command, and what spawned it? |
| 5 | Certutil download | What URL, and did the file execute afterwards? |
| 6 | Web shell upload / parameter | Was the upload successful (2xx), and is the path writable by the web user? |
| 7 | SSH brute force | Did a success follow the failures, from the same source? |
| 8 | New local user / cron | Is there a change ticket, and who owns the account or job? |

## 3. Standard triage steps

1. **Scope the host.** Pull every event for `host.name` in a ±30 minute window around the alert.
2. **Establish the parent chain.** For process alerts, walk `process.parent.*` upward until you reach a user action (browser, Office, explorer, sshd).
3. **Pivot on indicators.** Hash, command line fragment, source IP, service name, URL path. Search the whole index, not just the host.
4. **Check for follow-on activity.** A credential dump is only critical if it is used. Look for new logons, lateral movement, and service/task creation after it.
5. **Decide:** true positive, benign true positive, or false positive. Write the reason in one sentence a non-analyst could follow.
6. **Contain or escalate.** Document the recommended action even if you cannot take it.

## 4. Useful queries

Paste into Kibana Discover (`lab-*` data view), or adapt to `logs-*` for real data.

```kql
# everything from one host in a window
host.name : "WIN10-LAB" and @timestamp >= "now-30m"

# what did this process spawn?
process.parent.executable.caseless : *mimikatz.exe

# all authentication failures by source
event.category : "authentication" and event.outcome : "failure"

# web shell interaction
url.path : *shell.php or url.query : *cmd=*
```

Correlation by hand (the same logic `correlate.py` applies):

```json
POST lab-linux/_search
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "match_phrase": { "message": "Failed password" } },
    { "range": { "@timestamp": { "gte": "now-24h" } } }
  ]}},
  "aggs": {
    "by_ip": {
      "terms": { "field": "source.ip", "size": 20 },
      "aggs": { "per_minute": { "date_histogram": { "field": "@timestamp", "fixed_interval": "1m" } } }
    }
  }
}
```

## 5. Escalation criteria

Escalate to Tier 2 / IR when any of the following is true:

* A successful authentication follows a brute-force burst from the same source.
* LSASS access is followed by a new logon or lateral movement within 30 minutes.
* A service or scheduled task points at a binary in `C:\Users\Public`, `%TEMP%`, or `%APPDATA%`.
* A web shell upload returned 2xx and the path is writable by the web server user.
* Defense evasion (Defender disabled, logging cleared) precedes execution.

Close as false positive only with a named cause: a change ticket, a known installer, or a documented admin action. "Looks benign" is not a verdict.

## 6. End of shift

* Update `docs/tuning.md` if a rule produced a false positive.
* Add a case report under `cases/` for anything escalated.
* If a detection was wrong, change the rule, not the narrative.

## 7. Regenerate the published artifacts

The dashboard and coverage graphics are generated, committed, and checked by CI:

```powershell
.\.venv\Scripts\python.exe -m pipeline.detect --hours 24
.\.venv\Scripts\python.exe -m pipeline.report      # docs/index.html
.\.venv\Scripts\python.exe -m pipeline.publish     # site/ (public surface only)
.\.venv\Scripts\python.exe -m pipeline.coverage    # docs/attck-coverage.md
.\.venv\Scripts\python.exe -m pipeline.heatmap     # docs/assets/attck-heatmap.svg
```

Serve `site/` when you want to see exactly what Pages will publish. Serve `docs/` only for internal work, because it also contains the design notes and runbook.

Refresh the README hero screenshots after a dashboard change:

```powershell
.\.venv\Scripts\python.exe -m http.server 8765 --bind 127.0.0.1 --directory site

& "C:\Program Files\Google\Chrome\Application\chrome.exe" --headless=new `
  --disable-gpu --hide-scrollbars --force-device-scale-factor=1 `
  --user-data-dir="$env:TEMP\penumbra-chrome" --window-size=1440,1200 `
  --screenshot="$PWD\docs\assets\dashboard-corona.png" "http://localhost:8765/index.html?static=1&theme=corona"
```

Use `theme=umbra` and scroll to `#ledger` for the watch-floor image.

Commit the regenerated files together with the change that caused them.

