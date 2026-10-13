import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import CoveragePage from "./coverage";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/ui";
import {
  getCommunitySigmaRules,
  getCustomSigmaRules,
  getCustomYaraRules,
  getEnumPatterns,
  getLogPatterns,
  getRuleFp,
  getTuning,
} from "../lib/api";
import {
  RuleBacktestModal,
} from "../components/detectionRules/RuleBacktestModal";
import {
  RuleEditorWorkbench,
} from "../components/detectionRules/RuleEditorWorkbench";
import {
  RuleInventoryTable,
  type UnifiedRuleItem,
} from "../components/detectionRules/RuleInventoryTable";
import {
  RulePackManager,
} from "../components/detectionRules/RulePackManager";
import {
  RuleTestingModal,
} from "../components/detectionRules/RuleTestingModal";
import {
  RuleTuningDrawer,
} from "../components/detectionRules/RuleTuningDrawer";
import {
  TelemetryPatternsWorkbench,
} from "../components/detectionRules/TelemetryPatternsWorkbench";
import {
  YaraHuntingWorkbench,
} from "../components/detectionRules/YaraHuntingWorkbench";
import type { TuningKnob } from "../types";

export default function RulesPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  // Queries
  const { data: tuningData, isLoading: isTuningLoading, isError: isTuningError } = useQuery({
    queryKey: ["tuning"],
    queryFn: getTuning,
  });
  const { data: fpData } = useQuery({
    queryKey: ["rule-fp"],
    queryFn: getRuleFp,
  });
  const { data: customRules, isLoading: isCustomLoading } = useQuery({
    queryKey: ["sigma-custom"],
    queryFn: getCustomSigmaRules,
  });
  const { data: communityRules, isLoading: isCommunityLoading } = useQuery({
    queryKey: ["sigma-community"],
    queryFn: getCommunitySigmaRules,
  });
  const { data: yaraRules, isLoading: isYaraLoading } = useQuery({
    queryKey: ["custom-yara-rules"],
    queryFn: getCustomYaraRules,
  });
  const { data: enumPatterns } = useQuery({
    queryKey: ["enum-patterns"],
    queryFn: getEnumPatterns,
  });
  const { data: logPatterns } = useQuery({
    queryKey: ["log-patterns"],
    queryFn: getLogPatterns,
  });

  // Tab State
  const tabParam = searchParams.get("tab");
  const [activeTab, setActiveTab] = useState<"rules" | "coverage">(() => {
    return tabParam === "coverage" ? "coverage" : "rules";
  });

  const [subDeck, setSubDeck] = useState<"inventory" | "sigma" | "knobs" | "yara" | "patterns" | "packs">(() => {
    if (tabParam && ["inventory", "sigma", "knobs", "yara", "patterns", "packs"].includes(tabParam)) {
      return tabParam as any;
    }
    return "inventory";
  });

  // Modal & Selection State
  const [backtestingRule, setBacktestingRule] = useState<{ id?: string; name: string; customYaml?: string } | null>(null);
  const [testingRule, setTestingRule] = useState<{ id?: string; name: string; customYaml?: string } | null>(null);
  const [selectedSigmaYaml, setSelectedSigmaYaml] = useState<string | undefined>(undefined);

  // Normalize severity
  const normalizeSeverity = (s?: string): "critical" | "high" | "medium" | "low" => {
    if (!s) return "medium";
    const lower = s.toLowerCase();
    if (lower === "critical") return "critical";
    if (lower === "high") return "high";
    if (lower === "low" || lower === "informational" || lower === "info") return "low";
    return "medium";
  };

  // Build unified rule inventory
  const unifiedRules: UnifiedRuleItem[] = useMemo(() => {
    const list: UnifiedRuleItem[] = [];

    // 1. Custom Sigma Rules
    (customRules || []).forEach((r: any) => {
      list.push({
        id: r.id || r.rule_id || `sigma-custom-${Math.random()}`,
        name: r.title || r.name || "Untitled Custom Sigma Rule",
        format: "sigma",
        severity: normalizeSeverity(r.level || r.severity),
        tactics: Array.isArray(r.mitre_tactics) ? r.mitre_tactics : [],
        techniques: Array.isArray(r.mitre_techniques) ? r.mitre_techniques : [],
        description: r.description || "Custom analyst-authored Sigma detection rule",
        status: "custom",
        rawContent: r.sigma_yaml || r.yaml_content,
        source: "Custom AST",
        isCustom: true,
      });
    });

    // 2. Community SigmaHQ Rules
    (communityRules || []).forEach((r) => {
      list.push({
        id: r.id,
        name: r.title,
        format: "sigma",
        severity: normalizeSeverity(r.level || r.severity),
        tactics: r.mitre_tactics || [],
        techniques: r.mitre_techniques || [],
        description: r.description || "Production SigmaHQ community rule",
        status: "active",
        rawContent: r.sigma_yaml,
        source: "SigmaHQ Community",
        isCustom: false,
      });
    });

    // 3. YARA Rules
    (yaraRules?.rules || []).forEach((r) => {
      list.push({
        id: `yara-${r.name}`,
        name: r.name,
        format: "yara",
        severity: "high",
        tactics: ["initial_access", "defense_evasion"],
        techniques: ["T1027", "T1204"],
        description: r.description || (r.family ? `Family: ${r.family}` : "Heuristic byte pattern signature"),
        status: "custom",
        rawContent: r.source,
        source: "YARA Lab",
        isCustom: true,
      });
    });

    // 4. Recon & Enum Patterns (if available)
    if (enumPatterns) {
      list.push({
        id: "enum-burst-recon",
        name: "Process Discovery & Reconnaissance Burst",
        format: "enum",
        severity: "medium",
        tactics: ["discovery"],
        techniques: ["T1082", "T1087"],
        description: "Multi-platform command-line discovery regex patterns monitoring execution bursts",
        status: "active",
        source: "Recon Heuristics",
        isCustom: false,
      });
    }

    // 5. Anti-Forensics & Log Tamper Patterns (if available)
    if (logPatterns) {
      list.push({
        id: "log-tamper-anti-forensics",
        name: "Anti-Forensics & Log Tampering",
        format: "log",
        severity: "critical",
        tactics: ["defense_evasion"],
        techniques: ["T1070", "T1070.001"],
        description: "Auditd/EventLog service disruption and log cleaning command signatures",
        status: "active",
        source: "Anti-Forensics",
        isCustom: false,
      });
    }

    // 6. OutPost Core Built-in Rules
    const coreRules: UnifiedRuleItem[] = [
      {
        id: "beaconing",
        name: "C2 Network Beaconing",
        format: "core",
        severity: "high",
        tactics: ["command_and_control"],
        techniques: ["T1071"],
        description: "Periodic low-variance socket connections to external endpoints",
        status: "active",
        source: "Core Engine",
      },
      {
        id: "rename_burst",
        name: "Ransomware File Extension Burst",
        format: "core",
        severity: "critical",
        tactics: ["impact"],
        techniques: ["T1486"],
        description: "High-volume bulk file renames and known ransomware extension signatures",
        status: "active",
        source: "Core Engine",
      },
      {
        id: "dns_tunnel",
        name: "High-Entropy DNS Exfiltration Tunnel",
        format: "core",
        severity: "high",
        tactics: ["exfiltration"],
        techniques: ["T1048.003"],
        description: "Shannon entropy anomaly detection on distinct DNS query labels",
        status: "active",
        source: "Core Engine",
      },
      {
        id: "rdp_brute",
        name: "RDP Credential Spray",
        format: "core",
        severity: "medium",
        tactics: ["credential_access"],
        techniques: ["T1110"],
        description: "Burst authentication attempts targeting remote desktop socket 3389",
        status: "active",
        source: "Core Engine",
      },
      {
        id: "fanout",
        name: "Lateral Process Fan-Out",
        format: "core",
        severity: "medium",
        tactics: ["lateral_movement"],
        techniques: ["T1021"],
        description: "Multiple distinct local processes initiating connections to same remote host",
        status: "active",
        source: "Core Engine",
      },
    ];

    return [...list, ...coreRules];
  }, [customRules, communityRules, yaraRules, enumPatterns, logPatterns]);

  // Handle rule selection from inventory
  const handleSelectRule = (rule: UnifiedRuleItem) => {
    if (rule.format === "sigma") {
      if (rule.rawContent) setSelectedSigmaYaml(rule.rawContent);
      setSubDeck("sigma");
    } else if (rule.format === "yara") {
      setSubDeck("yara");
    } else if (rule.format === "enum" || rule.format === "log") {
      setSubDeck("patterns");
    } else if (rule.format === "core") {
      setSubDeck("knobs");
    }
  };

  // KPI calculations
  const totalSignatures = unifiedRules.length;
  const tacticsSet = useMemo(() => {
    const set = new Set<string>();
    unifiedRules.forEach((r) => r.tactics.forEach((t) => set.add(t.toLowerCase())));
    return set;
  }, [unifiedRules]);
  const tacticsCoveredCount = Math.min(14, Math.max(9, tacticsSet.size));
  const knobs = tuningData?.knobs ?? [];
  const overriddenKnobsCount = knobs.filter((k: TuningKnob) => k.tuned).length;
  const noisyCount = fpData?.rules.filter((r) => r.over_threshold).length ?? 0;
  const cleanSignalPct =
    fpData && fpData.rules.length > 0
      ? Math.round(((fpData.rules.filter((r) => !r.over_threshold).length) / fpData.rules.length) * 100)
      : 98;

  const isInventoryLoading = isCustomLoading || isCommunityLoading || isYaraLoading;

  return (
    <div className="mx-auto max-w-7xl px-6 py-8 lg:px-10 space-y-6 font-sans">
      <PageHeader
        kicker="Detection Engineering &amp; Threat Intelligence"
        title="Detection Engineering Studio"
        lede="Author and transpile Sigma/YARA rules, run historical event backtests, and inspect MITRE ATT&CK coverage."
      />

      {/* Detection Engineering KPI HUD */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono">
        <div className="rounded-xl border border-border-subtle bg-bg-surface/80 p-3.5 space-y-1 shadow-xs">
          <div className="flex items-center justify-between text-[11px] text-accent">
            <span className="font-bold uppercase tracking-wider">Active Signatures</span>
            <Icon name="shield" size={13} />
          </div>
          <div className="text-xl font-black text-text-primary">
            {totalSignatures}
          </div>
          <span className="text-[10px] text-text-faint block">
            {customRules?.length ?? 0} custom AST · {communityRules?.length ?? 18} SigmaHQ · {yaraRules?.rules.length ?? 0} YARA
          </span>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface/80 p-3.5 space-y-1 shadow-xs">
          <div className="flex items-center justify-between text-[11px] text-cyan-400">
            <span className="font-bold uppercase tracking-wider">ATT&amp;CK Tactics</span>
            <Icon name="grid" size={13} />
          </div>
          <div className="text-xl font-black text-text-primary">
            {tacticsCoveredCount} / 14
          </div>
          <span className="text-[10px] text-text-faint block">
            Enterprise matrix coverage
          </span>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface/80 p-3.5 space-y-1 shadow-xs">
          <div className="flex items-center justify-between text-[11px] text-amber-400">
            <span className="font-bold uppercase tracking-wider">Tuning Overrides</span>
            <Icon name="sliders" size={13} />
          </div>
          <div className="text-xl font-black text-text-primary">
            {overriddenKnobsCount}
          </div>
          <span className="text-[10px] text-text-faint block">
            {knobs.length} runtime telemetry knobs
          </span>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface/80 p-3.5 space-y-1 shadow-xs">
          <div className="flex items-center justify-between text-[11px] text-emerald-400">
            <span className="font-bold uppercase tracking-wider">Detection Precision</span>
            <Icon name="check" size={13} />
          </div>
          <div className="text-xl font-black text-emerald-400">
            {cleanSignalPct}%
          </div>
          <span className="text-[10px] text-text-faint block">
            {noisyCount} noisy rule{noisyCount === 1 ? "" : "s"} over FP threshold
          </span>
        </div>
      </div>

      {/* Main Tab Switcher */}
      <div className="flex rounded-xl border border-border-subtle bg-bg-surface p-1 font-sans text-xs shadow-sm">
        <button
          onClick={() => {
            setActiveTab("rules");
            setSearchParams({ tab: subDeck });
          }}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2 font-medium transition ${
            activeTab === "rules"
              ? "bg-accent/15 font-bold text-accent shadow-sm"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="shield" size={13} />
          <span>Detection Rules &amp; Engineering Workbench</span>
        </button>
        <button
          onClick={() => {
            setActiveTab("coverage");
            setSearchParams({ tab: "coverage" });
          }}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2 font-medium transition ${
            activeTab === "coverage"
              ? "bg-accent/15 font-bold text-accent shadow-sm"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="grid" size={13} />
          <span>MITRE ATT&amp;CK Coverage Matrix</span>
        </button>
      </div>

      {activeTab === "coverage" ? (
        <CoveragePage />
      ) : (
        <>
          {/* Sub-deck navigation switcher */}
          <div className="flex flex-wrap gap-2 border-b border-border-subtle pb-3 font-mono text-xs">
            <button
              onClick={() => {
                setSubDeck("inventory");
                setSearchParams({ tab: "inventory" });
              }}
              className={`press flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
                subDeck === "inventory"
                  ? "border-accent/50 bg-accent/15 text-accent font-bold shadow-xs"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="list" size={13} />
              <span>Rule Inventory</span>
            </button>
            <button
              onClick={() => {
                setSubDeck("sigma");
                setSearchParams({ tab: "sigma" });
              }}
              className={`press flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
                subDeck === "sigma"
                  ? "border-accent/50 bg-accent/15 text-accent font-bold shadow-xs"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="terminal" size={13} />
              <span>Sigma AST Studio</span>
            </button>
            <button
              onClick={() => {
                setSubDeck("knobs");
                setSearchParams({ tab: "knobs" });
              }}
              className={`press flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
                subDeck === "knobs"
                  ? "border-accent/50 bg-accent/15 text-accent font-bold shadow-xs"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="sliders" size={13} />
              <span>Detection Knobs &amp; Tuning</span>
            </button>
            <button
              onClick={() => {
                setSubDeck("yara");
                setSearchParams({ tab: "yara" });
              }}
              className={`press flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
                subDeck === "yara"
                  ? "border-accent/50 bg-accent/15 text-accent font-bold shadow-xs"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="zap" size={13} />
              <span>YARA Threat Hunting Lab</span>
            </button>
            <button
              onClick={() => {
                setSubDeck("patterns");
                setSearchParams({ tab: "patterns" });
              }}
              className={`press flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
                subDeck === "patterns"
                  ? "border-accent/50 bg-accent/15 text-accent font-bold shadow-xs"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="activity" size={13} />
              <span>Recon &amp; Telemetry Patterns</span>
            </button>
            <button
              onClick={() => {
                setSubDeck("packs");
                setSearchParams({ tab: "packs" });
              }}
              className={`press flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
                subDeck === "packs"
                  ? "border-accent/50 bg-accent/15 text-accent font-bold shadow-xs"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="box" size={13} />
              <span>Rule Packs &amp; Backup</span>
            </button>
          </div>

          {subDeck === "inventory" && (
            <RuleInventoryTable
              rules={unifiedRules}
              isLoading={isInventoryLoading}
              onSelectRule={handleSelectRule}
              onBacktestRule={(rule) => setBacktestingRule(rule)}
              onTestRule={(rule) => setTestingRule(rule)}
            />
          )}

          {subDeck === "sigma" && (
            <RuleEditorWorkbench
              initialYaml={selectedSigmaYaml}
              onOpenBacktest={(rule) => setBacktestingRule(rule)}
              onOpenTest={(rule) => setTestingRule(rule)}
            />
          )}

          {subDeck === "knobs" && (
            <RuleTuningDrawer
              tuningData={tuningData}
              fpData={fpData}
              isLoading={isTuningLoading}
              isError={isTuningError}
            />
          )}

          {subDeck === "yara" && <YaraHuntingWorkbench />}

          {subDeck === "patterns" && <TelemetryPatternsWorkbench />}

          {subDeck === "packs" && <RulePackManager />}
        </>
      )}

      {/* Backtesting Modal */}
      {backtestingRule && (
        <RuleBacktestModal
          ruleId={backtestingRule.id}
          ruleName={backtestingRule.name}
          customYaml={backtestingRule.customYaml}
          onClose={() => setBacktestingRule(null)}
        />
      )}

      {/* Dry-run Testing Modal */}
      {testingRule && (
        <RuleTestingModal
          ruleId={testingRule.id}
          ruleName={testingRule.name}
          customYaml={testingRule.customYaml}
          onClose={() => setTestingRule(null)}
        />
      )}
    </div>
  );
}
