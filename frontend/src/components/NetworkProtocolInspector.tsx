import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Icon } from "./Icon";
import { Panel } from "./ui";
import { getRunNetworkAnalysis, getSampleNetworkAnalysis } from "../lib/api";
import type { NetworkAnalysisResult } from "../types";

interface NetworkProtocolInspectorProps {
  runId?: string;
  sampleId?: string;
}

export const NetworkProtocolInspector: React.FC<NetworkProtocolInspectorProps> = ({ runId, sampleId }) => {
  const [activeSubTab, setActiveSubTab] = useState<"flows" | "dns" | "http" | "tls">("flows");
  const [filterQuery, setFilterQuery] = useState("");

  const { data, isLoading, isError } = useQuery<NetworkAnalysisResult>({
    queryKey: ["network-analysis", runId || sampleId],
    queryFn: () => (runId ? getRunNetworkAnalysis(runId) : getSampleNetworkAnalysis(sampleId!)),
    enabled: Boolean(runId || sampleId),
  });

  if (isLoading) {
    return (
      <Panel kicker="Network Telemetry Flow" title="Reconstructing Protocol Activity">
        <div className="flex items-center justify-center py-12 text-sm text-text-muted">
          <Icon name="refresh" className="mr-2 animate-spin text-accent" size={18} />
          Analyzing socket streams, DNS queries, and TLS handshakes...
        </div>
      </Panel>
    );
  }

  const metrics = data?.metrics ?? {
    total_dns_queries: 0,
    dga_suspect_count: 0,
    http_request_count: 0,
    suspicious_http_count: 0,
    tls_handshake_count: 0,
    unique_destinations_count: 0,
    unique_flows_count: 0,
  };
  const c2_beaconing = data?.c2_beaconing ?? {
    evaluated_endpoints: 0,
    beaconing_detected: false,
    beacon_count: 0,
    beacons: [],
    details_by_ip: {},
  };
  const dns_conversations = Array.isArray(data?.dns_conversations) ? data.dns_conversations : [];
  const http_requests = Array.isArray(data?.http_requests) ? data.http_requests : [];
  const tls_handshakes = Array.isArray(data?.tls_handshakes) ? data.tls_handshakes : [];
  const flows = Array.isArray(data?.flows) ? data.flows : [];

  if (
    isError ||
    !data ||
    (!metrics.unique_flows_count &&
      !metrics.total_dns_queries &&
      !metrics.http_request_count &&
      !metrics.tls_handshake_count &&
      dns_conversations.length === 0 &&
      http_requests.length === 0 &&
      tls_handshakes.length === 0 &&
      flows.length === 0)
  ) {
    return (
      <Panel kicker="Network Telemetry Flow" title="Network Telemetry">
        <p className="py-6 text-center text-sm text-text-muted">No protocol telemetry recorded or analyzed.</p>
      </Panel>
    );
  }

  const q = filterQuery.toLowerCase().trim();

  const filteredDns = dns_conversations.filter(
    (d) =>
      !q ||
      d.query.toLowerCase().includes(q) ||
      d.resolved_ips.some((ip) => ip.includes(q)) ||
      d.category.toLowerCase().includes(q),
  );

  const filteredHttp = http_requests.filter(
    (h) =>
      !q ||
      h.url.toLowerCase().includes(q) ||
      h.host.toLowerCase().includes(q) ||
      h.path.toLowerCase().includes(q) ||
      (h.process_name && h.process_name.toLowerCase().includes(q)),
  );

  const filteredTls = tls_handshakes.filter(
    (t) =>
      !q ||
      (t.sni && t.sni.toLowerCase().includes(q)) ||
      (t.dest_ip && t.dest_ip.includes(q)) ||
      (t.ja3 && t.ja3.toLowerCase().includes(q)) ||
      (t.known_tool && t.known_tool.toLowerCase().includes(q)),
  );

  const filteredFlows = flows.filter(
    (f) =>
      !q ||
      f.dest_ip.includes(q) ||
      String(f.dest_port).includes(q) ||
      (f.process_name && f.process_name.toLowerCase().includes(q)) ||
      f.protocol.toLowerCase().includes(q),
  );

  return (
    <div className="space-y-4">
      {/* Metrics Banner */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3">
          <div className="flex items-center gap-1.5 text-xs text-text-muted">
            <Icon name="network" size={12} className="text-accent" />
            <span>Total Flows</span>
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-text-normal">{metrics.unique_flows_count}</div>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3">
          <div className="flex items-center gap-1.5 text-xs text-text-muted">
            <Icon name="globe" size={12} className="text-sky-400" />
            <span>DNS Lookups</span>
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-text-normal">
            {metrics.total_dns_queries}
            {metrics.dga_suspect_count > 0 && (
              <span className="ml-1.5 font-mono text-xs font-semibold text-risk-malicious">
                ({metrics.dga_suspect_count} DGA)
              </span>
            )}
          </div>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3">
          <div className="flex items-center gap-1.5 text-xs text-text-muted">
            <Icon name="external" size={12} className="text-emerald-400" />
            <span>HTTP Requests</span>
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-text-normal">
            {metrics.http_request_count}
            {metrics.suspicious_http_count > 0 && (
              <span className="ml-1.5 font-mono text-xs font-semibold text-risk-suspicious">
                ({metrics.suspicious_http_count} sus)
              </span>
            )}
          </div>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3">
          <div className="flex items-center gap-1.5 text-xs text-text-muted">
            <Icon name="shield" size={12} className="text-indigo-400" />
            <span>TLS Handshakes</span>
          </div>
          <div className="mt-1 font-mono text-xl font-bold text-text-normal">{metrics.tls_handshake_count}</div>
        </div>

        <div
          className={`rounded-xl border p-3 ${
            c2_beaconing.beaconing_detected
              ? "border-risk-malicious/40 bg-risk-malicious/10"
              : "border-border-subtle bg-bg-elevated/40"
          }`}
        >
          <div className="flex items-center gap-1.5 text-xs text-text-muted">
            <Icon
              name="zap"
              size={12}
              className={c2_beaconing.beaconing_detected ? "animate-pulse text-risk-malicious" : "text-text-faint"}
            />
            <span>C2 Beaconing</span>
          </div>
          <div
            className={`mt-1 font-mono text-xl font-bold ${
              c2_beaconing.beaconing_detected ? "text-risk-malicious" : "text-text-muted"
            }`}
          >
            {c2_beaconing.beaconing_detected ? `${c2_beaconing.beacon_count} Flagged` : "Clean"}
          </div>
        </div>
      </div>

      {/* C2 Beaconing Alert Card (if detected) */}
      {c2_beaconing.beaconing_detected && (
        <div className="rounded-xl border border-risk-malicious/40 bg-risk-malicious/10 p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-risk-malicious">
            <Icon name="zap" size={16} className="animate-pulse" />
            <span>Automated Command-and-Control Beaconing Detected</span>
          </div>
          <p className="mt-1 text-xs text-text-muted">
            Statistical inter-arrival jitter analysis identified clock-synchronized communication channels matching
            adversary malleable C2 sleep masks:
          </p>
          <div className="mt-3 space-y-2">
            {c2_beaconing.beacons.map((b, idx) => (
              <div
                key={idx}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-risk-malicious/20 bg-bg-base/60 px-3 py-2 font-mono text-xs"
              >
                <div className="flex items-center gap-2">
                  <span className="font-bold text-risk-malicious">{b.dest_ip}</span>
                  <span className="rounded bg-risk-malicious/20 px-1.5 py-0.5 text-[10px] text-risk-malicious">
                    Score: {b.beaconing_score}/100
                  </span>
                  <span className="text-text-faint">({b.verdict})</span>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-text-muted">
                  <span>
                    Mean Interval: <strong className="text-text-normal">{b.interval_mean_sec}s</strong>
                  </span>
                  <span>
                    Jitter: <strong className="text-text-normal">{b.jitter_pct}%</strong>
                  </span>
                  <span>
                    Pulses: <strong className="text-text-normal">{b.connection_count}</strong>
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Navigation Sub-Tabs & Filter */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle pb-2">
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setActiveSubTab("flows")}
            className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold ${
              activeSubTab === "flows"
                ? "border border-accent/40 bg-accent/15 text-accent"
                : "text-text-muted hover:bg-bg-elevated hover:text-text-normal"
            }`}
          >
            <Icon name="network" size={13} />
            <span>Connection Flows ({flows.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveSubTab("dns")}
            className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold ${
              activeSubTab === "dns"
                ? "border border-sky-500/40 bg-sky-500/15 text-sky-400"
                : "text-text-muted hover:bg-bg-elevated hover:text-text-normal"
            }`}
          >
            <Icon name="globe" size={13} />
            <span>DNS Conversations ({dns_conversations.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveSubTab("http")}
            className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold ${
              activeSubTab === "http"
                ? "border border-emerald-500/40 bg-emerald-500/15 text-emerald-400"
                : "text-text-muted hover:bg-bg-elevated hover:text-text-normal"
            }`}
          >
            <Icon name="external" size={13} />
            <span>HTTP Requests ({http_requests.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveSubTab("tls")}
            className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold ${
              activeSubTab === "tls"
                ? "border border-indigo-500/40 bg-indigo-500/15 text-indigo-400"
                : "text-text-muted hover:bg-bg-elevated hover:text-text-normal"
            }`}
          >
            <Icon name="shield" size={13} />
            <span>TLS Handshakes ({tls_handshakes.length})</span>
          </button>
        </div>

        <div className="relative">
          <input
            type="text"
            placeholder="Filter protocol items..."
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            className="w-48 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-xs text-text-normal placeholder:text-text-faint focus:border-accent focus:outline-none"
          />
        </div>
      </div>

      {/* Sub-tab 1: Connection Flows */}
      {activeSubTab === "flows" && (
        <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-elevated/20">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border-subtle bg-bg-elevated/60 text-[11px] font-semibold text-text-muted">
              <tr>
                <th className="px-3 py-2">Protocol</th>
                <th className="px-3 py-2">Destination Socket</th>
                <th className="px-3 py-2">Process Attribution</th>
                <th className="px-3 py-2">Reputation & Threat Notes</th>
                <th className="px-3 py-2 text-right">Packets/Hits</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50 font-mono">
              {filteredFlows.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-6 text-center text-text-faint">
                    No matching flows recorded.
                  </td>
                </tr>
              ) : (
                filteredFlows.map((f, idx) => (
                  <tr key={idx} className="hover:bg-bg-elevated/40">
                    <td className="px-3 py-2 font-bold uppercase text-accent">{f.protocol}</td>
                    <td className="px-3 py-2">
                      <span className="font-semibold text-text-normal">{f.dest_ip}</span>
                      <span className="text-text-faint">:{f.dest_port}</span>
                    </td>
                    <td className="px-3 py-2 text-text-muted">
                      {f.process_name || "—"} {f.pid ? <span className="text-[10px] text-text-faint">(PID {f.pid})</span> : ""}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                            f.reputation === "malicious"
                              ? "bg-risk-malicious/20 text-risk-malicious"
                              : f.reputation === "suspicious"
                              ? "bg-risk-suspicious/20 text-risk-suspicious"
                              : "bg-risk-clean/15 text-risk-clean"
                          }`}
                        >
                          {f.reputation}
                        </span>
                        {f.threat_indicators.map((ti, i) => (
                          <span key={i} className="text-[10px] text-text-faint">
                            · {ti}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-right text-text-muted">{f.connection_count}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Sub-tab 2: DNS Conversations */}
      {activeSubTab === "dns" && (
        <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-elevated/20">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border-subtle bg-bg-elevated/60 text-[11px] font-semibold text-text-muted">
              <tr>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Domain Name</th>
                <th className="px-3 py-2">Category</th>
                <th className="px-3 py-2">DGA Score</th>
                <th className="px-3 py-2">Resolved IP(s)</th>
                <th className="px-3 py-2 text-right">Queries</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50 font-mono">
              {filteredDns.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-text-faint">
                    No DNS conversations recorded.
                  </td>
                </tr>
              ) : (
                filteredDns.map((d, idx) => (
                  <tr key={idx} className="hover:bg-bg-elevated/40">
                    <td className="px-3 py-2 font-bold text-sky-400">{d.record_type}</td>
                    <td className="px-3 py-2">
                      <span className="font-semibold text-text-normal">{d.query}</span>
                      {d.threat_indicators.length > 0 && (
                        <div className="mt-0.5 text-[10px] text-risk-suspicious">{d.threat_indicators.join(" · ")}</div>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                          d.is_dga_suspect
                            ? "bg-risk-malicious/20 text-risk-malicious"
                            : d.category !== "Standard"
                            ? "bg-risk-suspicious/20 text-risk-suspicious"
                            : "bg-bg-base text-text-muted"
                        }`}
                      >
                        {d.category}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`font-bold ${
                          d.dga_score >= 0.65
                            ? "text-risk-malicious"
                            : d.dga_score >= 0.4
                            ? "text-risk-suspicious"
                            : "text-text-muted"
                        }`}
                      >
                        {d.dga_score.toFixed(2)}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-text-muted">
                      {d.resolved_ips.length > 0 ? d.resolved_ips.join(", ") : "—"}
                    </td>
                    <td className="px-3 py-2 text-right text-text-muted">{d.query_count}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Sub-tab 3: HTTP Web Requests */}
      {activeSubTab === "http" && (
        <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-elevated/20">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border-subtle bg-bg-elevated/60 text-[11px] font-semibold text-text-muted">
              <tr>
                <th className="px-3 py-2">Method</th>
                <th className="px-3 py-2">URI Path & Host</th>
                <th className="px-3 py-2">Destination Socket</th>
                <th className="px-3 py-2">Process</th>
                <th className="px-3 py-2">Threat Indicators</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50 font-mono">
              {filteredHttp.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-6 text-center text-text-faint">
                    No HTTP requests captured.
                  </td>
                </tr>
              ) : (
                filteredHttp.map((h, idx) => (
                  <tr key={idx} className="hover:bg-bg-elevated/40">
                    <td className="px-3 py-2">
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                          h.method === "POST"
                            ? "bg-amber-500/20 text-amber-400"
                            : h.method === "PUT"
                            ? "bg-purple-500/20 text-purple-400"
                            : "bg-emerald-500/20 text-emerald-400"
                        }`}
                      >
                        {h.method}
                      </span>
                    </td>
                    <td className="max-w-xs truncate px-3 py-2" title={h.url}>
                      <span className="font-semibold text-text-normal">{h.path}</span>
                      <div className="text-[10px] text-text-faint">{h.host}</div>
                    </td>
                    <td className="px-3 py-2 text-text-muted">
                      {h.dest_ip}:{h.dest_port}
                    </td>
                    <td className="px-3 py-2 text-text-muted">{h.process_name || "—"}</td>
                    <td className="px-3 py-2">
                      {h.threat_indicators.length > 0 ? (
                        <div className="space-y-0.5">
                          {h.threat_indicators.map((ti, i) => (
                            <span key={i} className="inline-block rounded bg-risk-malicious/15 px-1.5 py-0.5 text-[10px] text-risk-malicious">
                              {ti}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-text-faint">Standard</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Sub-tab 4: TLS Handshakes */}
      {activeSubTab === "tls" && (
        <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-elevated/20">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border-subtle bg-bg-elevated/60 text-[11px] font-semibold text-text-muted">
              <tr>
                <th className="px-3 py-2">Destination Socket</th>
                <th className="px-3 py-2">Server Name Indication (SNI)</th>
                <th className="px-3 py-2">JA3 Client Hash</th>
                <th className="px-3 py-2">Matched C2 / Tool Signature</th>
                <th className="px-3 py-2">Process</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50 font-mono">
              {filteredTls.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-6 text-center text-text-faint">
                    No TLS handshakes recorded.
                  </td>
                </tr>
              ) : (
                filteredTls.map((t, idx) => (
                  <tr key={idx} className="hover:bg-bg-elevated/40">
                    <td className="px-3 py-2 font-semibold text-text-normal">
                      {t.dest_ip}:{t.dest_port}
                    </td>
                    <td className="px-3 py-2 text-indigo-400">{t.sni || "—"}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-text-muted">{t.ja3 || "—"}</td>
                    <td className="px-3 py-2">
                      {t.known_tool ? (
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                            t.severity === "malicious"
                              ? "bg-risk-malicious/20 text-risk-malicious"
                              : "bg-risk-suspicious/20 text-risk-suspicious"
                          }`}
                        >
                          <Icon name="shield" size={10} className="mr-1 inline" />
                          {t.known_tool}
                        </span>
                      ) : (
                        <span className="text-text-faint">Generic Client</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-text-muted">{t.process_name || "—"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
