## What changed

<!-- One or two sentences. Link the detection gap, bug, or design decision. -->

## Type

- [ ] New or changed Sigma rule
- [ ] Correlation spec
- [ ] Pipeline or CI
- [ ] Dashboard or design
- [ ] Documentation

## Verification

Paste the commands you ran and their result. At minimum:

```powershell
python -m pipeline.lint
python -m pipeline.compile --check
python -m pipeline.coverage --check
python -m pytest
```

## Checklist

- [ ] Sigma remains the source of truth; generated artifacts were rebuilt, not hand-edited.
- [ ] Every changed rule has `description`, `references`, `falsepositives`, `level`, and ATT&CK tags.
- [ ] Generated coverage, heatmap, and compiled rules are committed together with the rule.
- [ ] No real logs, credentials, personal data, or non-documentation IP addresses were added.
- [ ] Screenshots were refreshed if the dashboard changed.
- [ ] The change is documented in the README, runbook, or tuning log when it changes behaviour.
