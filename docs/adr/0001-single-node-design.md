# ADR 0001: Single-Node Architecture Design

## Status
Accepted

## Context
Security Operations Centers (SOCs), incident response teams, and homelab / air-gapped security researchers require an endpoint detection, response, and artifact triage platform that can be deployed rapidly without managing distributed microservices, container orchestrators (Kubernetes), or external message brokers (Kafka/RabbitMQ). Traditional commercial EDR solutions impose heavy infrastructure overhead, requiring multi-node clusters, dedicated database administrators, and complex network ingress.

## Decision
OutPost is engineered as a self-contained, single-node architecture where the core backend, detection pipeline, artifact analyzer, and storage engines execute within a single lightweight process or container.

Key architectural properties:
- Fast startup: boots in under 1 second on standard commodity hardware.
- Local SQLite primary store with optional PostgreSQL backend.
- Synchronous or worker-pool based detection without external message queues.
- Local filesystem artifact vault with restricted POSIX permissions (`0600`).
- Unified API serving both the React 19 web cockpit and the CLI/TUI.

## Alternatives Rejected
1. **Distributed Microservice Cluster (Kubernetes / gRPC):**
   - *Reason for Rejection:* Immense operational complexity, excessive memory overhead (>8 GB idle), and difficult deployment in isolated, air-gapped forensic enclaves.
2. **External Message Broker Architecture (Kafka / RabbitMQ):**
   - *Reason for Rejection:* Operational fragility during emergency forensic triage; complex cluster state and disk queuing dependencies when inspecting malicious binaries.

## Consequences & Known Costs
- **Pros:**
  - Zero-dependency deployment: single binary / script bootstrap.
  - Predictable latency and memory footprints (<150 MB base RAM).
  - Effortless backup and disaster recovery (single SQLite file or atomic dump).
- **Cons / Limitations:**
  - Vertical scaling limit: a single OutPost instance is scoped for fleets of 1 to 5,000 active endpoints.
  - High Availability (HA) failover relies on systemd service restarts or active-passive node replication rather than distributed consensus.
