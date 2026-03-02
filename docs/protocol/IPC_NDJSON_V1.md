# Sentinel IPC NDJSON Protocol v1.0

## Overview
Sentinel plugins communicate with the host over a byte-stream transport using NDJSON
(Newline-Delimited JSON). Each line is one complete JSON object.

## Transport
A **stream transport** is required. Implementations MAY support multiple transports.

- Recommended: **Unix domain stream socket**
  - Listen spec: `unix:/tmp/sentinel.sock`
  - Path-only shorthand MAY be supported: `/tmp/sentinel.sock`
- Optional (useful in constrained environments): **TCP loopback**
  - Listen spec: `tcp:127.0.0.1:7777`
  - SHOULD bind to loopback by default.
- Enterprise mode: **TCP loopback + mTLS**
  - Listen spec: `tcp+tls:127.0.0.1:7777` (or `tcps:127.0.0.1:7777`)
  - Host and plugin require:
    - `SENTINEL_TLS_CERT_FILE`
    - `SENTINEL_TLS_KEY_FILE`
    - `SENTINEL_TLS_CA_FILE`
  - Plugin optional:
    - `SENTINEL_TLS_SERVER_NAME` (defaults to `localhost`)

## Framing
- UTF-8 only.
- Exactly one JSON object per line (`\n` delimiter).
- Messages MUST NOT contain embedded newlines.
- Hosts SHOULD enforce limits:
  - Max line length: 64 KiB
  - Max metrics per `PushMetrics`: 500
  - Rate limiting/backpressure per connection
  - Current host implementation enforces max line bytes and rejects over-limit payloads with
    `{"status":"bad_request","error":"line_too_long"}`; override via
    `SENTINEL_IPC_MAX_LINE_BYTES` (`1024..=1048576`).
  - Current host implementation enforces stream read timeout via
    `SENTINEL_IPC_READ_TIMEOUT_MS` (`1000..=300000`, default `30000`).
  - Current host implementation enforces per-connection message cap via
    `SENTINEL_IPC_MAX_MESSAGES_PER_CONN` (`1..=1000000`, default `10000`).
  - Current host implementation denies non-loopback TCP binds by default unless
    `SENTINEL_ALLOW_NON_LOOPBACK_BIND=1` is explicitly set.
  - Current host implementation validates Unix socket parent directory permissions and
    refuses group/world-accessible parents unless
    `SENTINEL_IPC_ALLOW_INSECURE_DIR_PERMS=1` is explicitly set.

## Requests (NDJSON)
All requests are JSON objects tagged by `type` with `payload` as the content.
Requests MAY include an `id` field. If present, the host SHOULD echo it in responses.

### Register
```json
{"type":"Register","payload":{"plugin_id":"example.rust"}}
```

```json
{"id":"01HV...","type":"Register","payload":{"plugin_id":"example.rust"}}
```

### PushMetrics
```json
{"type":"PushMetrics","payload":{"metrics":[
  {"source":"example.rust","label":"Fan Speed","value":"100%"}
]}}
```

### ProposeAction
```json
{"type":"ProposeAction","payload":{
  "title":"Restart nginx",
  "cmd":"systemctl restart nginx",
  "dangerous":true
}}
```

## Responses (NDJSON)
The host replies with exactly one NDJSON line per request.

### Success
```json
{"status":"ok"}
```

```json
{"status":"ok","id":"01HV..."}
```

### Failure
```json
{"status":"bad_request"}
```

```json
{"status":"bad_request","id":"01HV..."}
```

## Security Recommendations
- Unix sockets SHOULD be placed in a user-owned directory with 0700 and socket 0600.
- TCP transport SHOULD bind only to loopback (127.0.0.1) by default.
- For enterprise deployments, `tcp+tls` SHOULD be used with mandatory client-certificate auth.
- Host/plugin TLS key files SHOULD be owner-only readable on Unix; current implementation enforces this by default.
- Host/plugin TLS key files SHOULD NOT be symlinks; current implementation enforces this by default.
- Hosts SHOULD validate inputs and enforce limits to avoid plugin-induced denial-of-service.
