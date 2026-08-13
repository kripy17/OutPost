"""Process tree builder — pid/ppid events → nested tree.

Logic per docs/02-BACKEND-SPEC.md: build a {pid: node} map from all
`process_create` events for a run, attach each node to its ppid's children,
and return the roots (processes whose ppid never appears in the run).

`annotate_process_tree` attaches the docs/07 signature visual: every node
that made an outbound connection carries the worst reputation of the IPs it
reached (risk halo) plus the IP list itself.
"""

import os

from ..core.schema import ProcessNode, Reputation


def _node_name(ev: dict, pid: int) -> str:
    """Node label: process_name, falling back to the resolved exe_path
    basename (auditd exe= / Sysmon Image) so a nameless row renders as its
    real binary instead of the anonymous pid-N placeholder."""
    name = ev.get("process_name")
    if not name:
        exe = (ev.get("exe_path") or "").strip()
        name = os.path.basename(exe.replace("\\", "/")) if exe else ""
    return name or f"pid-{pid}"


def build_process_tree(events: list[dict]) -> list[ProcessNode]:
    """Given process_create event dicts, return the list of root ProcessNodes."""
    nodes: dict[int, ProcessNode] = {}

    # Create/merge nodes from events (a pid may appear in several events).
    for ev in events:
        pid = ev.get("pid")
        if pid is None or ev.get("event_type") != "process_create":
            continue
        node = nodes.get(pid)
        if node is None:
            node = ProcessNode(
                pid=pid,
                ppid=ev.get("ppid"),
                process_name=_node_name(ev, pid),
                command_line=ev.get("command_line"),
            )
            nodes[pid] = node
        else:
            # A later event may carry a better name/command line.
            if not node.process_name.startswith("pid-") and ev.get("process_name"):
                node.process_name = ev["process_name"]
            if ev.get("command_line") and not node.command_line:
                node.command_line = ev["command_line"]

    # Attach children. Roots are nodes whose ppid is absent from this run
    # (or points to itself — a safe guard against malformed data).
    roots: list[ProcessNode] = []
    for node in nodes.values():
        parent = nodes.get(node.ppid) if node.ppid is not None else None
        if parent is not None and parent.pid != node.pid:
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
