# Edge Release Ops

This runbook covers the generic Tardigrade release path used by portfolio apps that sit behind a localhost upstream.

## Minimum Checks

Before promotion:

- verify `GET /health` returns `200`
- verify TLS cert and key paths are readable by the service user
- verify bearer auth by making one authenticated request to a protected route and one unauthenticated request expecting `401`
- verify the upstream loopback target configured by `TARDIGRADE_UPSTREAM_BASE_URL` is healthy

After promotion:

- tail the JSON access log and confirm `correlation_id`, `status`, and `identity` fields are present
- confirm the session store file updates when session-backed flows are enabled
- confirm the transcript store file appends NDJSON records for proxied chat or command requests
- confirm the approval store file remains writable when approval-gated routes are enabled

## File Paths

Recommended persistent files:

- session store: `TARDIGRADE_SESSION_STORE_PATH`
- approval store: `TARDIGRADE_APPROVAL_STORE_PATH`
- transcript store: `TARDIGRADE_TRANSCRIPT_STORE_PATH`

## Dashboard Inputs

Standard portfolio dashboard inputs from Tardigrade today:

- `GET /health`
- JSON access logs from `TARDIGRADE_ACCESS_LOG_FORMAT=json`
- error log output from `TARDIGRADE_ERROR_LOG_PATH`

Prometheus-style metrics should only be wired into the shared dashboard once the runtime route is enabled in the serving surface used by the target deployment.
