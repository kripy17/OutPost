# ADR 0004: In-Process Synchronous vs. Worker Detection Pipeline

## Status
Accepted

## Context
When telemetry batches arrive from endpoints, detection rules (Sigma-based behavioural patterns, MITRE ATT&CK techniques, process parentage anomalies) must evaluate incoming events. System designers must choose between evaluating detections inline within the ingest request lifecycle or delegating to an asynchronous worker pool via a distributed queue (e.g. Celery / Redis).

## Decision
OutPost utilizes a hybrid tiered architecture:
1. **Synchronous In-Process Normalization and Primary Detection:**
   - Ingested batches undergo stream normalization and fast-path rule evaluation inline during `POST /ingest/batch`.
   - Python-native pre-compiled detection sets (pre-indexed by event category, command-line tokens, and provider) evaluate hundreds of rules in under 2 milliseconds per batch.
   - Deduped alerts and findings are immediately written to the database in the same transaction as raw events.
2. **Worker-Isolated Deep Analysis and Sandbox Detonation:**
   - Heavyweight static analysis (PE/ELF parsing, disassembly, YARA rule compilation, entropy analysis) and dynamic sandboxing run in separate worker processes with strict resource limits (`setrlimit`, CPU and memory caps) to prevent hung jobs or untrusted parsing vulnerabilities from impacting the API server.

## Alternatives Rejected
1. **Full Asynchronous Ingestion (Dumping raw events to Redis / Kafka with deferred detection):**
   - *Reason for Rejection:* Introduces alert latency (events arrive but alerts appear seconds or minutes later), requires multi-service orchestration, and complicates live interactive forensic investigation where the analyst expects immediate feedback.
2. **Synchronous Full Sandboxing Inline with Ingestion:**
   - *Reason for Rejection:* Detonating or parsing large malware samples takes seconds to minutes and would exhaust HTTP server worker threads, causing HTTP request timeouts.

## Consequences & Known Costs
- **Pros:**
  - Zero-latency detection: an attacker executing `whoami /priv` or `mimikatz` generates an alert visible on screen within the same HTTP roundtrip.
  - No external queuing daemons required.
- **Cons / Limitations:**
  - Ingestion throughput per thread is bound by CPU rule evaluation time. Scaling beyond 50,000 events/second requires multiple worker processes or multi-core load balancing.
