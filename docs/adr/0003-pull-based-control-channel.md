# ADR 0003: Pull-Based Agent Control and Ingest Channel

## Status
Accepted

## Context
Endpoint sensors (Linux eBPF/auditd, Windows Sysmon, macOS EndpointSecurity) run across diverse network topologies, including NAT, firewalled user workstations, remote laptops, and cloud subnets. Server-to-agent push architectures require opening inbound network ports on every protected endpoint, configuring firewall traversal, and managing complex reverse proxies.

## Decision
OutPost adopts a pull-based, outbound-only connection architecture:
- Endpoints initiate all communication outbound to the OutPost backend over HTTP/HTTPS.
- Ingestion is batched: telemetry is buffered locally on the endpoint in an encrypted/protected ring buffer and pushed via `POST /ingest/batch`.
- Remediation, containment, and forensic hunt commands are polled via heartbeat payloads (`POST /agents/heartbeat` or `POST /agents/{host_id}/heartbeat`).
- When an analyst orders host isolation (`isolate`) or process termination (`kill`), the command is queued in `host_actions` and returned to the agent in the response to its next heartbeat.
- Agent acknowledges command receipt via `POST /agents/{host_id}/actions/ack` and reports completion with status and exit code.

## Alternatives Rejected
1. **Direct Inbound Push (SSH / WinRM / Open Agent Port):**
   - *Reason for Rejection:* Severe security risk (opens attack surface on every endpoint), breaks behind NAT and zero-trust perimeter firewalls, requires managing endpoint inbound firewall credentials.
2. **Persistent Bi-directional WebSocket / gRPC Streams:**
   - *Reason for Rejection:* Stateful connections require significant server memory and connection pooling per agent; fragile across roaming laptop network handoffs and sleeping machines.

## Consequences & Known Costs
- **Pros:**
  - Zero inbound firewall requirements on endpoints.
  - Resilience across laptop disconnects, network drops, and sleep cycles.
  - Authenticated via per-agent HMAC-SHA256 headers without exposing endpoints to network scanners.
- **Cons / Limitations:**
  - Remediation latency is bounded by the agent's heartbeat interval (default: 5 to 15 seconds). Emergency containment is near-real-time but not instantaneous (sub-second).
