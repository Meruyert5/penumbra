# Security policy

## This is a lab, not a product

Penumbra ships a deliberately insecure Elasticsearch/Kibana stack:

* security and TLS are disabled;
* ports `9200` and `5601` bind to localhost by default;
* credentials in config files are placeholders.

**Never expose this stack to an untrusted network.** If you adapt it, put it behind a firewall and enable Elasticsearch security before loading anything sensitive.

## Supported versions

Only the current `main` branch is maintained. There are no supported release branches.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private vulnerability reporting:

1. Go to the **Security** tab of the repository.
2. Choose **Report a vulnerability**.
3. Include reproduction steps, affected files, and the impact you expect.

You can expect an acknowledgement within a few days. This is a personal portfolio project, so fixes are best-effort, but credible reports will be prioritised and credited unless you prefer otherwise.

## Scope

The lab threat model is in [`docs/threat-model.md`](docs/threat-model.md). In scope:

* the Python pipeline (`pipeline/`), Docker configuration, and CI workflows;
* rule logic that could cause unsafe query behaviour;
* the generated dashboard (XSS or data-handling issues).

Out of scope:

* the intentional lab-only posture (disabled auth, localhost HTTP);
* alerts produced from synthetic telemetry;
* vulnerabilities in Elasticsearch, Kibana, or Filebeat themselves. Report those upstream.

## Handling data

All telemetry in this repository is synthetic. Do not submit real logs, credentials, or personal data in issues or pull requests.
