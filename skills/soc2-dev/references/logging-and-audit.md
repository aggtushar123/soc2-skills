# Logging, Audit Trail, and Monitoring

This domain covers what the system records about security-relevant activity, how that record is protected from tampering and leakage, and how operators find out when something is wrong. It serves CC7.2 (system monitoring and anomaly detection), CC7.3 (evaluating and responding to security events), CC6.1 (logical access, via the audit trail that proves access controls work), CC4.1 (monitoring of controls), C1.2 (confidentiality of logged data), and A1.1 / CC7.1 (availability and health monitoring). Auditors treat the audit log as the primary evidence that every other control actually fired; if an event is not logged, the control is unprovable.

## When Claude must load this file

- Adding, changing, or removing a logger call (`logger.info`, `log.error`, `console.log`, `print` used for logging)
- Introducing or reconfiguring a logging library (pino, winston, structlog, zap, logback, slog, log4j2, Serilog)
- Writing or modifying any login, MFA, password, permission, role, or admin code path (an audit event is required)
- Adding code that reads or exports restricted or confidential data
- Adding a configuration-change endpoint, feature-flag toggle, or admin action
- Touching log shipping, log sinks, or retention config (Fluent Bit, Vector, CloudWatch, Datadog, Loki, Splunk, OpenSearch)
- Adding or editing alert rules, monitors, dashboards, or on-call routing (PagerDuty, Opsgenie, Grafana alerting)
- Adding or changing health, readiness, or liveness endpoints, or SLO definitions
- Handling timestamps, time zones, or `Date.now()` / `time.time()` in anything persisted
- Serializing request or response objects, exceptions, or user records into a log line

## Requirements

### LOG-01 — Security-relevant events are audit-logged

**Rule:** Every security-relevant event is written to the audit log: login success and failure, MFA enrollment and challenge results, password and permission changes, role grants and revocations, access to restricted data, admin actions, configuration changes, data exports, and deletions. Silent security operations are a finding.

**TSC:** CC7.2, CC6.1

**How to implement:**
- Create a single `audit.emit(event)` function (or `AuditLogger` class) and forbid ad-hoc audit writes. Every event in the catalog below goes through it.
- Emit the event inside the same code path as the action, after the outcome is known, so failures are recorded as well as successes. Emit failures on `except`/`catch` before re-raising.
- For access to restricted data, emit at the repository or data-access layer (one place), not per endpoint, so new endpoints cannot forget it.
- Treat the event catalog as a contract: add a test that asserts an audit event is emitted for each listed action (`assert audit_sink.last().event_type == "auth.login.failure"`).
- Use a Semgrep or custom lint rule that flags functions matching `*login*`, `*password*`, `*role*`, `*grant*`, `*export*`, `*delete*` in service layers with no `audit.emit` call.
- Batch or async emission is acceptable, but the event must be durably enqueued before the HTTP response is returned. Never fire-and-forget without a persistent buffer.

**Code example:**

```python
# services/auth.py
from audit import audit  # SOC2:LOG-01 single emitter for all security events

def login(request, email: str, password: str):
    user = users.find_by_email(email)
    ok = user is not None and verify_password(user, password)
    audit.emit(
        event_type="auth.login.success" if ok else "auth.login.failure",
        actor_id=user.id if user else None,
        actor_type="user",
        target_type="user",
        target_id=user.id if user else email_hash(email),
        action="login",
        outcome="success" if ok else "failure",
        request=request,          # ip, user_agent, correlation_id, tenant_id derived here
    )
    if not ok:
        raise AuthenticationError()
    return issue_session(user)
```

**Minimum event catalog:**

| Event name | When emitted | Requirement |
|------------|--------------|-------------|
| `auth.login.success` | Credentials and MFA accepted, session issued | LOG-01 |
| `auth.login.failure` | Bad credentials, unknown user, locked account | LOG-01 |
| `auth.logout` | User or admin terminates a session | LOG-01 |
| `auth.mfa.enrolled` / `auth.mfa.removed` | MFA factor added or deleted | LOG-01 |
| `auth.mfa.challenge` | MFA challenge attempted, with outcome | LOG-01 |
| `auth.password.changed` / `auth.password.reset_requested` | Password changed or reset flow initiated | LOG-01 |
| `auth.session.revoked` | Session or refresh token revoked server-side | LOG-01 |
| `authz.role.granted` / `authz.role.revoked` | Role or permission assigned or removed | LOG-01 |
| `authz.permission.denied` | Server-side authorization check failed | LOG-01 |
| `user.created` / `user.deactivated` / `user.deleted` | Provisioning lifecycle | LOG-01 |
| `admin.action` | Any action performed via an admin role, with `action` naming it | LOG-01 |
| `admin.user.impersonated` | Support or admin assumed another user's identity | LOG-01 |
| `data.restricted.read` | Read of a field or record classified restricted | LOG-01 |
| `data.exported` | Bulk export, report download, or API bulk fetch | LOG-01 |
| `data.deleted` | Hard delete or subject-erasure execution | LOG-01 |
| `config.changed` | Runtime setting, feature flag, or integration credential changed | LOG-01 |
| `secret.rotated` | Secret or key rotation performed | LOG-01 |
| `apikey.created` / `apikey.revoked` | API key or service credential lifecycle | LOG-01 |

**Common violations:**
- Login failures are logged only at `debug` level in the application log, not as audit events.
- Admin panel actions go through a generic `update()` handler that emits nothing.
- Data exports (CSV download, reporting API) are treated as ordinary reads and never audited.
- Audit emission is wrapped in `try/except: pass`, so sink outages silently drop events.

**Evidence to produce:**
- Path to the audit emitter module and the test file asserting events per catalog entry.
- A log query (e.g. Datadog `service:api @event_type:auth.login.failure`) returning events for a sampled date range.
- Grep output of `SOC2:LOG-01` annotations across service modules.

### LOG-02 — Audit entries are complete, append-only, and separate

**Rule:** Each audit entry records actor, action, target, UTC timestamp, source IP or client identifier, outcome, and correlation ID. Audit logs are append-only and stored separately from application logs.

**TSC:** CC7.2, CC7.3

**How to implement:**
- Define the schema once as a typed object (Pydantic model, TypeScript interface, Go struct, Protobuf). Reject emission if a required field is missing; do not default `actor_id` to `"unknown"` silently.
- Store audit events in a sink with no update or delete path from the application identity: an append-only table with `INSERT` grant only, an S3 bucket with Object Lock (compliance mode), CloudWatch Logs with a resource policy that denies `DeleteLogStream`, or a dedicated Datadog/Loki index with restricted retention edits.
- Ship audit events through a separate stream or index (`audit-*`) from application logs so retention, access, and alerting can differ.
- Populate `correlation_id` from the inbound request ID (`X-Request-ID` or OpenTelemetry trace ID) so audit entries join to application traces.
- Include `actor_type` (`user`, `service`, `system`, `admin`) so machine actions are distinguishable from human ones.
- Hash-chain or sign batches if the sink cannot guarantee immutability (e.g. store `prev_hash` and `hash` per row).

**Code example:**

Audit event schema (JSON):

```json
{
  "event_type": "authz.role.granted",
  "actor_id": "usr_01J8Z5X2K3",
  "actor_type": "admin",
  "target_type": "user",
  "target_id": "usr_01J8Z9Q7M1",
  "action": "grant_role:billing_admin",
  "outcome": "success",
  "ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0 (Macintosh) Chrome/128.0",
  "correlation_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "timestamp": "2026-09-14T08:41:07.213Z",
  "tenant_id": "ten_acme"
}
```

Append-only sink (Terraform):

```hcl
# SOC2:LOG-02 audit bucket is write-once; application role can only PutObject
resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 400
    }
  }
}

data "aws_iam_policy_document" "audit_writer" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/*"]
  }
  # no s3:DeleteObject, no s3:PutObjectRetention, no s3:BypassGovernanceRetention
}
```

**Common violations:**
- Audit rows live in the main application database with the same role that runs `DELETE` for other tables.
- `actor_id` is missing for background jobs; the entry says what happened but not who or what triggered it.
- Timestamps are written in server local time or as epoch integers without a timezone contract.
- Audit and application logs share an index; a retention change for noisy app logs also truncates audit history.

**Evidence to produce:**
- Schema definition file path and the IAM policy or DB grant export showing insert-only access.
- Object Lock or retention-lock configuration export for the audit sink.
- Sample of 5 audit entries showing all required fields populated.

### LOG-03 — No secrets or unmasked PII in logs

**Rule:** Logs never contain passwords, tokens, API keys, session IDs, full card numbers, or unmasked PII. A redaction layer runs before log lines leave the process.

**TSC:** C1.2, CC6.1

**How to implement:**
- Configure redaction at the logger level, not per call site: pino `redact`, winston custom `format`, structlog processor, zap `Encoder` wrapper, logback `MaskingPatternLayout`.
- Use a deny-list of key names (`password`, `passwd`, `secret`, `token`, `authorization`, `cookie`, `set-cookie`, `api_key`, `apikey`, `private_key`, `ssn`, `card_number`, `cvv`) matched case-insensitively at any nesting depth, plus regex patterns for bearer tokens, JWTs, AWS keys (`AKIA[0-9A-Z]{16}`), and PANs (Luhn-checked 13-19 digits).
- For entities that carry PII, prefer an allow-list: log `user.id` and `user.tenant_id` only, never the whole object. Implement `__repr__` / `toJSON` / `String()` on domain models to return only safe fields.
- Never log raw request bodies, headers, or exceptions with locals. If you must log a body for debugging, log a hash and length.
- Run a second redaction pass in the shipper (Vector `remap`, Fluent Bit `modify`/Lua filter, Datadog Sensitive Data Scanner) as defense in depth.
- Add a CI test that logs a fixture containing every sensitive pattern and asserts the captured output contains `[REDACTED]` and none of the raw values.

**Code example:**

```typescript
// logger.ts
import pino from "pino";

// SOC2:LOG-03 deny-list redaction applied before any transport
export const logger = pino({
  level: process.env.LOG_LEVEL ?? "info",
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: [
      "password", "*.password", "*.passwd", "*.secret", "*.token",
      "req.headers.authorization", "req.headers.cookie", "res.headers[\"set-cookie\"]",
      "*.api_key", "*.apiKey", "*.private_key", "*.ssn", "*.card_number", "*.cvv",
      "user.email", "user.phone", "user.dob",
    ],
    censor: "[REDACTED]",
  },
  serializers: {
    // allow-list: only stable identifiers leave the process
    user: (u: { id: string; tenantId: string }) => ({ id: u.id, tenant_id: u.tenantId }),
    err: pino.stdSerializers.err,
  },
});
```

**Common violations:**
- `logger.info("login attempt", { body: req.body })` on the login route, capturing plaintext passwords.
- Exception handlers log `err` with a stack that includes a connection string or bearer token in a URL.
- Redaction is applied only in production config; staging logs leak the same data and are shipped to the same SIEM.
- Email addresses and phone numbers are treated as "not really PII" and logged freely.

**Evidence to produce:**
- Logger configuration file path showing the redact list and serializers.
- CI job name and test file for the redaction fixture test.
- Sensitive Data Scanner or shipper filter configuration export.

### LOG-04 — Structured, centralized, retained, write-restricted

**Rule:** Logs are structured JSON, shipped to a central system, retained for at least the configured period (default 1 year), and only the shipping identity can write to them.

**TSC:** CC7.2, CC4.1

**How to implement:**
- Emit one JSON object per line to stdout/stderr; let the platform collector (Fluent Bit, Vector, CloudWatch agent, Datadog agent, Promtail) ship it. Do not write log files inside containers.
- Include base fields on every line: `timestamp`, `level`, `service`, `env`, `version`, `correlation_id`, `trace_id`, `span_id`. OpenTelemetry log bridges do this automatically.
- Set retention explicitly in the sink (CloudWatch `retention_in_days`, Datadog index retention plus archive to S3, Loki `retention_period`, OpenSearch ISM policy). Read the period from `.soc2/config.yml` when generating IaC.
- Restrict write access to the collector's identity (IAM role for the agent, Datadog API key scoped to logs, Loki tenant token). Developers get read access via the UI, never direct write or delete.
- Archive to cold object storage with encryption for the long tail (Datadog Archives, CloudWatch export to S3 with lifecycle rules).
- Alert on log volume dropping to zero for any service (a silent pipeline is a control failure).

**Code example:**

```go
// main.go
import (
    "log/slog"
    "os"
)

// SOC2:LOG-04 JSON to stdout; collector ships to central sink with 400-day retention
func newLogger(service, version, env string) *slog.Logger {
    h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelInfo,
        ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
            if a.Key == slog.TimeKey {
                a.Value = slog.StringValue(a.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z07:00"))
            }
            return a
        },
    })
    return slog.New(h).With("service", service, "version", version, "env", env)
}
```

```hcl
resource "aws_cloudwatch_log_group" "api" {
  name              = "/svc/api"
  retention_in_days = 400   # SOC2:LOG-04 >= configured 1-year retention
  kms_key_id        = aws_kms_key.logs.arn
}
```

**Common violations:**
- Free-text `printf` logs that cannot be queried by field; auditors cannot filter by actor or outcome.
- CloudWatch log groups created with `retention_in_days = null` (never expire) in dev but `7` in production.
- Engineers hold `logs:DeleteLogGroup` or Datadog admin in production.
- Logs written to a local file on a host that is replaced on every deploy.

**Evidence to produce:**
- Terraform or console export of log group / index retention settings.
- IAM policy export for the collector role and for the developer read-only role.
- Screenshot or query showing a log line from 11+ months ago still retrievable.

### LOG-05 — Alerts on security signals with an on-call owner

**Rule:** Alerts exist for repeated authentication failures, privilege escalation, new admin creation, error-rate spikes, and unavailable dependencies. Every alert routes to a named on-call rotation.

**TSC:** CC7.2, CC7.3

**How to implement:**
- Define alerts as code (Datadog monitors via Terraform, Grafana alert rules, Prometheus `PrometheusRule`, CloudWatch metric filters plus alarms). Alerts configured only in a UI are not reviewable.
- Minimum security monitors: `auth.login.failure` > N per actor or IP in 5 minutes; any `authz.role.granted` where role is admin; any `user.created` with admin role; `authz.permission.denied` spike; `admin.user.impersonated`; `config.changed` outside a deploy window.
- Minimum operational monitors: HTTP 5xx rate above SLO burn threshold; dependency health check failing (database, cache, queue, third-party API); log volume zero; audit sink write errors > 0.
- Route through PagerDuty/Opsgenie with an escalation policy. The monitor definition must reference a team or service, not an individual's email.
- Include a runbook link in every alert message. Record acknowledgement and resolution (the incident tool does this automatically).
- Test alerts quarterly by injecting a synthetic event (e.g. run a scripted 20 failed logins against staging) and keep the incident record as evidence.

**Code example:**

```hcl
# monitors/security.tf
# SOC2:LOG-05 brute-force detection routed to on-call
resource "datadog_monitor" "auth_failure_burst" {
  name    = "[SEC] Repeated login failures per source IP"
  type    = "log alert"
  query   = <<-EOT
    logs("service:api @event_type:auth.login.failure")
      .index("audit").rollup("count").by("@ip").last("5m") > 20
  EOT
  message = <<-EOT
    {{@ip.name}} produced {{value}} failed logins in 5m.
    Runbook: https://runbooks.internal/sec/brute-force
    @pagerduty-security-oncall
  EOT
  monitor_thresholds { critical = 20 }
  tags = ["team:security", "soc2:LOG-05"]
}

resource "datadog_monitor" "admin_role_granted" {
  name    = "[SEC] Admin role granted"
  type    = "log alert"
  query   = "logs(\"@event_type:authz.role.granted @action:grant_role\\:*admin*\").index(\"audit\").rollup(\"count\").last(\"5m\") > 0"
  message = "Admin grant by {{@actor_id.name}} to {{@target_id.name}}. Verify ticket. @pagerduty-security-oncall"
  monitor_thresholds { critical = 0 }
}
```

**Common violations:**
- Alerts exist for CPU and disk but nothing fires on authentication or authorization events.
- Alert notifications go to a Slack channel nobody is paged from; no acknowledgement trail.
- Monitors are muted indefinitely after a noisy week and never re-enabled.
- No alert on the audit pipeline itself; a broken shipper goes unnoticed for weeks.

**Evidence to produce:**
- Path to the monitors-as-code directory and the list of monitor names with their routing targets.
- PagerDuty/Opsgenie escalation policy export for the security service.
- Incident records from the last quarterly synthetic alert test.

### LOG-06 — Health checks and SLO monitoring

**Rule:** Every service exposes health (liveness) and readiness endpoints. Uptime and latency are monitored against documented SLOs.

**TSC:** A1.1, CC7.1

**How to implement:**
- Expose `/healthz` (process alive, no dependencies) and `/readyz` (dependencies reachable: DB ping, cache ping, required config loaded). Return 200/503 with a small JSON body; never include stack traces or connection strings.
- Wire them into the orchestrator: Kubernetes `livenessProbe`/`readinessProbe`, ECS container health check, ALB target-group health check. Readiness failing must remove the instance from rotation.
- Keep health endpoints unauthenticated but restricted to the internal network or load balancer; do not expose dependency detail publicly.
- Document SLOs in the repo (`docs/slo.md` or `.soc2/slo.yml`): availability target (e.g. 99.9% monthly), p95 latency target per critical endpoint, error budget policy.
- Monitor from outside the cluster (Datadog Synthetics, Pingdom, CloudWatch Synthetics, Grafana synthetic monitoring) so a dead cluster still produces an alert.
- Export SLI metrics via OpenTelemetry or Prometheus (`http_server_duration`, `http_requests_total`) and build burn-rate alerts (fast: 2% budget in 1 h; slow: 5% in 6 h).

**Code example:**

```yaml
# k8s/api-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: registry.internal/api:1.42.0
          ports: [{ containerPort: 8080 }]
          # SOC2:LOG-06 orchestrator-driven health and readiness
          livenessProbe:
            httpGet: { path: /healthz, port: 8080 }
            initialDelaySeconds: 10
            periodSeconds: 10
            failureThreshold: 3
          readinessProbe:
            httpGet: { path: /readyz, port: 8080 }
            periodSeconds: 5
            failureThreshold: 2
```

**Common violations:**
- `/health` always returns 200 regardless of database connectivity, so traffic is routed to instances that fail every request.
- SLOs live in a slide deck, not the repo, and no monitor references them.
- Only internal metrics are monitored; a DNS or load-balancer outage produces no alert.
- Health endpoint returns dependency hostnames and versions to the public internet.

**Evidence to produce:**
- Path to the SLO document and to the deployment manifest with probes.
- Synthetic monitor configuration and 90-day uptime report export.

### LOG-07 — UTC timestamps and synchronized clocks

**Rule:** All timestamps written to logs, audit entries, and databases are UTC in ISO-8601. Hosts and containers synchronize time with a trusted source.

**TSC:** CC7.2

**How to implement:**
- Configure every logger to emit ISO-8601 UTC with millisecond precision and a trailing `Z` (pino `isoTime`, structlog `TimeStamper(fmt="iso", utc=True)`, zap `ISO8601TimeEncoder` after `time.UTC()`, logback `%d{yyyy-MM-dd'T'HH:mm:ss.SSSXXX, UTC}`).
- Store database timestamps as `timestamptz` (PostgreSQL) or `DATETIME` interpreted as UTC (MySQL with `time_zone='+00:00'`). Set the connection session timezone to UTC in the DSN or pool init.
- Set `TZ=UTC` in container images and process environments; never rely on host locale.
- Use the cloud provider's time service (Amazon Time Sync `169.254.169.123`, Google NTP `metadata.google.internal`) via chrony on hosts; managed Kubernetes nodes and serverless runtimes already do this, document that.
- Ban `datetime.now()` without `tz=timezone.utc`, `new Date().toString()`, and `time.Now()` without `.UTC()` in persisted paths with a lint rule (Semgrep `python.lang.best-practice.datetime-now-without-tz` or a custom rule).
- Convert to local time only at the presentation layer, using the viewer's timezone.

**Code example:**

```python
# logging_config.py
import structlog

# SOC2:LOG-07 every log line carries an ISO-8601 UTC timestamp
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp"),
        structlog.processors.JSONRenderer(),
    ],
)
```

```dockerfile
# Dockerfile
FROM python:3.12-slim
ENV TZ=UTC            # SOC2:LOG-07 container clock and libc default to UTC
RUN ln -sf /usr/share/zoneinfo/UTC /etc/localtime
```

**Common violations:**
- Servers in `Asia/Kolkata` local time produce audit entries that cannot be correlated with UTC cloud provider logs.
- Mixed formats across services: epoch seconds in one, epoch millis in another, RFC 2822 in a third.
- Self-managed VMs with no NTP client; clock drift of minutes breaks event ordering during incident review.
- Timestamps formatted with the user's timezone at write time and stored without offset.

**Evidence to produce:**
- Logger configuration file paths showing UTC formatting; DB session timezone setting.
- `chronyc tracking` output or cloud provider documentation reference for managed time sync.

## Review checklist

- [ ] LOG-01 — Does every new login, MFA, password, role, admin, restricted-data, export, delete, or config-change path emit an event from the catalog through the single audit emitter?
- [ ] LOG-02 — Does each audit event carry actor, actor_type, action, target, outcome, ip, user_agent, correlation_id, tenant_id, and a UTC timestamp, and is it written to the append-only audit sink rather than the application log?
- [ ] LOG-03 — Are no request bodies, headers, tokens, passwords, card numbers, or unmasked PII logged, and does the logger-level redaction config cover any new sensitive field names introduced?
- [ ] LOG-04 — Are new log lines structured JSON with the base fields, and does any new log sink or log group set retention to at least the configured period with write access limited to the collector identity?
- [ ] LOG-05 — If this change introduces a new security-relevant event or dependency, is there an alert-as-code rule for it that routes to an on-call rotation with a runbook link?
- [ ] LOG-06 — Does any new service or deployment expose `/healthz` and `/readyz`, wire them into the orchestrator, and reference a documented SLO with an external monitor?
- [ ] LOG-07 — Are all persisted timestamps UTC ISO-8601, and is any new container or host configured with `TZ=UTC` and time synchronization?
