"""Process tree builder — pid/ppid events → nested tree.

Logic per docs/02-BACKEND-SPEC.md: build a compound process map from all
`process_create` events for a run, attach each node to its parent,
and return the roots (processes whose ppid never appears in the run).

`annotate_process_tree` attaches the docs/07 signature visual: every node
that made an outbound connection carries the worst reputation of the IPs it
reached (risk halo) plus the IP list itself.
"""

import os

from ..core.schema import ProcessNode


def _node_name(ev: dict, pid: int) -> str:
    """Node label: process_name, falling back to the resolved exe_path
    basename (auditd exe= / Sysmon Image) so a nameless row renders as its
    real binary instead of the anonymous pid-N placeholder."""
    name = ev.get("process_name")
    if not name:
        exe = (ev.get("exe_path") or "").strip()
        name = os.path.basename(exe.replace("\\", "/")) if exe else ""
    return name or f"pid-{pid}"


def make_process_key(
    host_id: str | None = None,
    boot_id: str | None = None,
    pid: int | None = None,
    start_time: str | None = None,
) -> str:
    """Format compound process identity: host_id + boot_id + pid + start_time."""
    h = str(host_id or "local").strip().lower()
    b = str(boot_id or "default").strip().lower()
    p = str(pid if pid is not None else 0)
    s = str(start_time or "").strip()
    return f"{h}:{b}:{p}:{s}"


def build_process_tree(events: list[dict]) -> list[ProcessNode]:
    """Given process_create event dicts, return the list of root ProcessNodes
    using compound process identity to disambiguate PID reuse."""
    nodes: dict[str, ProcessNode] = {}
    # Index by (host_id, boot_id, pid) -> list of (start_time, node)
    host_boot_pid_nodes: dict[tuple[str, str, int], list[tuple[str, ProcessNode]]] = {}

    # Sort events by timestamp so processes are assembled chronologically
    sorted_events = sorted(
        (ev for ev in events if ev.get("pid") is not None and ev.get("event_type") == "process_create"),
        key=lambda e: str(e.get("process_start_time") or e.get("timestamp") or ""),
    )

    for ev in sorted_events:
        pid = ev["pid"]
        host_id = str(ev.get("host_id") or "local").strip().lower()
        boot_id = str(ev.get("boot_id") or "default").strip().lower()
        start_time = str(ev.get("process_start_time") or ev.get("timestamp") or "").strip()
        key = make_process_key(host_id, boot_id, pid, start_time)

        # If an event exists with this exact compound key, merge
        if key in nodes:
            node = nodes[key]
            name = _node_name(ev, pid)
            if name and (node.process_name.startswith("pid-") or not ev.get("process_name")):
                node.process_name = name
            if ev.get("command_line") and not node.command_line:
                node.command_line = ev["command_line"]
        else:
            # Check if there is already an existing node with matching (host, boot, pid) and no start_time
            legacy_key = make_process_key(host_id, boot_id, pid, "")
            if not start_time and legacy_key in nodes:
                node = nodes[legacy_key]
                name = _node_name(ev, pid)
                if name and (node.process_name.startswith("pid-") or not ev.get("process_name")):
                    node.process_name = name
                if ev.get("command_line") and not node.command_line:
                    node.command_line = ev["command_line"]
                continue

            node = ProcessNode(
                pid=pid,
                ppid=ev.get("ppid"),
                process_name=_node_name(ev, pid),
                command_line=ev.get("command_line"),
                host_id=host_id,
                boot_id=boot_id,
                process_start_time=start_time or None,
            )
            nodes[key] = node
            hbp_key = (host_id, boot_id, pid)
            if hbp_key not in host_boot_pid_nodes:
                host_boot_pid_nodes[hbp_key] = []
            host_boot_pid_nodes[hbp_key].append((start_time, node))

    # Attach children to parents.
    # Disambiguate parent using compound identity: match parent with same (host, boot, ppid)
    # started at or before the child.
    roots: list[ProcessNode] = []
    for node in nodes.values():
        if node.ppid is None:
            roots.append(node)
            continue

        hbp_key = (node.host_id or "local", node.boot_id or "default", node.ppid)
        candidates = host_boot_pid_nodes.get(hbp_key, [])

        # If not found under exact (host, boot), fallback across any host/boot for backward compatibility
        if not candidates:
            for (_ch, _cb, cpid), clist in host_boot_pid_nodes.items():
                if cpid == node.ppid:
                    candidates.extend(clist)

        parent = None
        if candidates:
            child_time = node.process_start_time or ""
            # Filter candidates started <= child_time (or any if timestamps absent)
            valid = [c for c in candidates if not child_time or not c[0] or c[0] <= child_time]
            if valid:
                # Pick the parent started closest to child
                parent = max(valid, key=lambda c: c[0])[1]
            else:
                parent = candidates[0][1]

        if parent is not None and parent is not node:
            parent.children.append(node)
        else:
            roots.append(node)

    return roots


# Reputation severity for computing a node's worst (halo) reputation.
_REP_RANK = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}


def annotate_process_tree(
    roots: list[ProcessNode],
    pid_ips: dict[int, list[str]],
    ip_reputation: dict[str, str],
) -> None:
    """Attach per-node network risk, in place (mutates the tree).

    `pid_ips` maps pid → distinct dest IPs (from network_connection events);
    `ip_reputation` maps dest IP → reputation label (enrichment output). A node
    with no outbound connections keeps both fields null/empty. Unknown IPs are
    ranked above clean so a connection to uncharacterized infrastructure still
    draws an analyst's eye.
    """

    def visit(node: ProcessNode) -> None:
        ips = pid_ips.get(node.pid, [])
        if ips:
            node.network_ips = sorted(ips)
            worst = max(
                ips,
                key=lambda ip: _REP_RANK.get(ip_reputation.get(ip, "unknown"), 0),
            )
            rep = ip_reputation.get(worst) or "unknown"
            # Halo semantics (docs/07): a halo signals *risk* — malicious,
            # suspicious, or uncharacterized (unknown). Clean-only nodes get
            # network_ips populated but flagged_reputation null: reaching
            # known-good infrastructure is NOT a finding.
            node.flagged_reputation = (
                rep if rep in _REP_RANK and rep != "clean" else None
            )
        for child in node.children:
            visit(child)

    for root in roots:
        visit(root)
