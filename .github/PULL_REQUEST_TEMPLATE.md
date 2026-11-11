## What changed

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The detection gap, bug, or documentation problem this fixes. -->

## Verification

<!-- Paste the commands you ran and the relevant output. -->

```powershell
.\.venv\Scripts\python.exe -m pipeline.lint
.\.venv\Scripts\python.exe -m pipeline.compile
.\.venv\Scripts\python.exe -m pipeline.coverage
.\.venv\Scripts\python.exe -m pytest
```

## Checklist

- [ ] Sigma rules were edited, not `rules/compiled/`
- [ ] Generated artifacts (`rules/compiled/`, `docs/attck-coverage.md`, `docs/assets/attck-heatmap.svg`) are committed
- [ ] Tests cover the new behaviour or the fix
- [ ] No real telemetry, credentials, or personal data added
- [ ] Documentation updated where behaviour changed
