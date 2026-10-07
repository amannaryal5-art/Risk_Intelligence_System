"use client";

import { useEffect, useMemo, useState } from "react";
import { useDropzone } from "react-dropzone";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Toaster, toast } from "sonner";
import { api, ScanResult } from "./api";

export type View = "scan" | "file" | "fusion" | "graph" | "dns" | "soar" | "history" | "detail";
export type Stored = { id: string; at: string; input: string; kind: string; result: ScanResult };

const scanSchema = z.object({ target: z.string().trim().min(2, "Enter a URL, IP, domain, hash, email, or message.") });

function detect(target: string) {
  const value = target.trim();
  if (/^[a-f\d]{32}$|^[a-f\d]{40}$|^[a-f\d]{64}$/i.test(value)) return "hash";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return "ip";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "email";
  if (/^(https?:\/\/|www\.)/i.test(value)) return "url";
  if (/^[a-z\d-]+(?:\.[a-z\d-]+)+$/i.test(value)) return "domain";
  return "text";
}

function score(result: ScanResult) {
  return Number(result.risk_score ?? result.score ?? result.max_ioc_score ?? result.confidence ?? 0);
}

function risk(result: ScanResult) {
  const value = String(result.risk_level ?? result.overall_risk ?? result.verdict ?? "unknown").toLowerCase();
  if (value === "minimal" || value === "safe" || value === "clean") return "low";
  if (value === "danger" || value === "malicious") return "critical";
  return value;
}

function toBase64(bytes: Uint8Array) {
  let binary = "";
  const len = bytes.byteLength;
  const chunk = 8192;
  for (let i = 0; i < len; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function action(level: string) {
  return level === "critical" || level === "high"
    ? "Do not open or execute. Block indicator at border firewalls, isolate endpoints, and preserve telemetry."
    : level === "medium"
    ? "Exercise caution. Perform secondary channel verification before allowing traffic or interactions."
    : "No strong malicious signatures detected. Proceed with baseline organizational security awareness.";
}

export default function Console() {
  const [view, setView] = useState<View>("scan");
  const [activeTarget, setActiveTarget] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [fileAnalysis, setFileAnalysis] = useState<any>(null);
  const [fusionData, setFusionData] = useState<any>(null);
  const [graphData, setGraphData] = useState<any>(null);
  const [dnsData, setDnsData] = useState<any>(null);
  const [soarData, setSoarData] = useState<any>(null);
  const [history, setHistory] = useState<Stored[]>([]);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("all");

  const form = useForm<z.infer<typeof scanSchema>>({
    resolver: zodResolver(scanSchema),
    defaultValues: { target: "" },
  });

  useEffect(() => {
    try {
      setHistory(JSON.parse(localStorage.getItem("crie-history") ?? "[]"));
    } catch {
      setHistory([]);
    }
  }, []);

  function remember(input: string, kind: string, data: ScanResult) {
    const next = [{ id: crypto.randomUUID(), at: new Date().toISOString(), input, kind, result: data }, ...history].slice(0, 50);
    setHistory(next);
    localStorage.setItem("crie-history", JSON.stringify(next));
    setResult(data);
    setActiveTarget(input);
  }

  // Unified Scan Submit
  async function submitScan({ target }: z.infer<typeof scanSchema>) {
    const kind = detect(target);
    setBusy(true);
    setActiveTarget(target);
    const toastId = toast.loading(kind === "text" ? "Running local heuristic scoring & IOC extraction…" : "Querying threat intelligence feeds…");
    try {
      let data: ScanResult;
      if (kind === "url" || kind === "domain") {
        data = await api("/api/v1/website-intel", { method: "POST", body: JSON.stringify({ url: target }) });
      } else if (kind === "email") {
        data = await api("/api/v1/scamcheck", { method: "POST", body: JSON.stringify({ input: target, detectedType: "email" }) });
      } else if (kind === "ip" || kind === "hash") {
        data = await api("/api/v1/threat-intel", { method: "POST", body: JSON.stringify(kind === "ip" ? { ips: [target] } : { hashes: [target] }) });
      } else {
        data = await api("/api/v1/analyze", { method: "POST", body: JSON.stringify({ text: target }) });
      }
      toast.success("Intelligence scan complete", { id: toastId });
      remember(target, kind, data);
      setView("scan");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Scan failed", { id: toastId });
    } finally {
      setBusy(false);
    }
  }

  // Deep File & Malware Sandbox
  async function fileScan(file: File) {
    setBusy(true);
    const toastId = toast.loading("Analyzing PE headers, section entropy, and suspicious APIs…");
    try {
      const buffer = await file.arrayBuffer();
      const base64Content = toBase64(new Uint8Array(buffer));
      const data = await api<any>("/api/v1/malware/deep-analysis", {
        method: "POST",
        body: JSON.stringify({ filename: file.name, content_base64: base64Content }),
      });
      toast.success("Binary analysis complete", { id: toastId });
      setFileAnalysis(data);
      remember(file.name, "file", data);
      setView("file");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "File analysis failed", { id: toastId });
    } finally {
      setBusy(false);
    }
  }

  // SOC Cyber Fusion Trigger
  async function runCyberFusion(target: string) {
    setBusy(true);
    const toastId = toast.loading("Computing 6-Module SOC Cyber Fusion model…");
    try {
      const isUrl = target.startsWith("http://") || target.startsWith("https://") || target.includes(".");
      const payload = isUrl ? { website_url: target } : { text: target };
      const data = await api<any>("/api/v1/cyber-fusion", { method: "POST", body: JSON.stringify(payload) });
      toast.success("Cyber Fusion telemetry ready", { id: toastId });
      setFusionData(data);
      setView("fusion");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Cyber Fusion computation failed", { id: toastId });
    } finally {
      setBusy(false);
    }
  }

  // Threat Graph Trigger
  async function runThreatGraph(target: string, kind = "domain") {
    setBusy(true);
    const toastId = toast.loading("Synthesizing node-link IOC topology…");
    try {
      const data = await api<any>("/api/v1/threat-graph", {
        method: "POST",
        body: JSON.stringify({ target, kind, scan_data: result || undefined }),
      });
      toast.success("Threat graph generated", { id: toastId });
      setGraphData(data);
      setView("graph");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Threat graph build failed", { id: toastId });
    } finally {
      setBusy(false);
    }
  }

  // DNS & Email Auditor Trigger
  async function runDnsAudit(domain: string) {
    setBusy(true);
    const toastId = toast.loading("Auditing SPF, DMARC, MX, and Certificate Transparency logs…");
    try {
      const data = await api<any>("/api/v1/audit/domain-dns", {
        method: "POST",
        body: JSON.stringify({ domain }),
      });
      toast.success("DNS security audit complete", { id: toastId });
      setDnsData(data);
      setView("dns");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "DNS audit failed", { id: toastId });
    } finally {
      setBusy(false);
    }
  }

  // SOAR Defense Generator Trigger
  async function runSoarPlaybook(target: string) {
    setBusy(true);
    const toastId = toast.loading("Generating firewall blocklists, Suricata signatures, and playbooks…");
    try {
      const kind = detect(target);
      const payload: any = { title: `CRIE Automated Mitigation for ${target}` };
      if (kind === "ip") payload.ips = [target];
      else if (kind === "domain") payload.domains = [target];
      else if (kind === "url") payload.urls = [target];
      else if (kind === "hash") payload.hashes = [target];
      else payload.domains = [target];

      const data = await api<any>("/api/v1/soar/generate-rules", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      toast.success("Defensive playbooks generated", { id: toastId });
      setSoarData(data);
      setView("soar");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "SOAR generation failed", { id: toastId });
    } finally {
      setBusy(false);
    }
  }

  const currentKind = detect(form.watch("target") || "");
  const visibleHistory = useMemo(
    () => history.filter((item) => filter === "all" || risk(item.result) === filter),
    [history, filter]
  );

  return (
    <main>
      <Toaster theme="dark" richColors position="top-right" />
      <header>
        <div className="brand">
          <span className="mark">◈</span>
          <div>
            <b>CRIE</b>
            <small>Enterprise Threat Intelligence</small>
          </div>
        </div>

        <nav>
          {(
            [
              { id: "scan", label: "Workbench" },
              { id: "file", label: "Malware Sandbox" },
              { id: "fusion", label: "SOC Fusion" },
              { id: "graph", label: "Threat Graph" },
              { id: "dns", label: "DNS / Email Audit" },
              { id: "soar", label: "SOAR Defenses" },
              { id: "history", label: "History & Reports" },
            ] as const
          ).map((item) => (
            <button
              key={item.id}
              className={view === item.id ? "active" : ""}
              onClick={() => setView(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="connection">
          <i />
          <span>Core Online</span>
        </div>
      </header>

      {/* 1. WORKBENCH VIEW */}
      {view === "scan" && (
        <section className="workspace">
          <div className="eyebrow">INTELLIGENCE WORKBENCH</div>
          <h1>Know before you click.</h1>
          <p className="lede">
            Enterprise triage for suspicious URLs, IPs, domains, hashes, and phishing messages with live multi-feed enrichment.
          </p>

          <form className="command" onSubmit={form.handleSubmit(submitScan)}>
            <textarea
              aria-label="Scan target"
              placeholder="Paste a URL, IP, domain, hash, email, or suspicious message…"
              {...form.register("target")}
            />
            <button disabled={busy}>{busy ? "Scanning…" : "Run Scan"}</button>
          </form>

          {form.formState.errors.target && <p className="error">{form.formState.errors.target.message}</p>}
          <p className="hint">
            Target Type: <b>{currentKind}</b> · Auto-routed to {currentKind === "text" ? "local heuristics & regex" : "threat feed reputation engine"}
          </p>

          {result ? (
            <div>
              <ResultCard
                result={result}
                onDetail={() => setView("detail")}
                onGraph={() => runThreatGraph(activeTarget || String(result.input || "target"), detect(activeTarget || "domain"))}
                onSoar={() => runSoarPlaybook(activeTarget || String(result.input || "target"))}
                onFusion={() => runCyberFusion(activeTarget || String(result.input || "target"))}
              />
            </div>
          ) : (
            <EmptyState text="Enter an indicator above to begin automated threat triage." />
          )}
        </section>
      )}

      {/* 2. FILE & MALWARE SANDBOX VIEW */}
      {view === "file" && (
        <section className="workspace">
          <div className="eyebrow">MALWARE & BINARY STATIC SANDBOX</div>
          <h1>Deep Payload Inspection</h1>
          <p className="lede">
            Inspects Portable Executable (PE) headers, section Shannon entropy, suspicious Windows APIs, and generates custom YARA rules.
          </p>

          <FileDropPanel onFile={fileScan} busy={busy} />

          {fileAnalysis && <FileAnalysisDetails data={fileAnalysis} onSoar={() => runSoarPlaybook(fileAnalysis.sha256)} />}
        </section>
      )}

      {/* 3. SOC CYBER FUSION VIEW */}
      {view === "fusion" && (
        <section className="workspace">
          <div className="eyebrow">SOC CYBER FUSION CENTER</div>
          <h1>Multi-Pillar Risk Telemetry</h1>
          <p className="lede">
            Correlates attack surface exposure, dark web telemetry, phishing coercion, and vulnerabilities into unified SOC modules.
          </p>

          <div className="command" style={{ margin: "20px 0" }}>
            <input
              type="text"
              placeholder="Enter domain or phishing text (e.g., example.com)..."
              defaultValue={activeTarget || ""}
              id="fusionInput"
            />
            <button
              onClick={() => {
                const val = (document.getElementById("fusionInput") as HTMLInputElement)?.value;
                if (val) runCyberFusion(val);
                else toast.error("Enter a domain or text message");
              }}
              disabled={busy}
            >
              Analyze Fusion
            </button>
          </div>

          {fusionData ? (
            <CyberFusionDetails data={fusionData} />
          ) : (
            <EmptyState text="Run a fusion scan above to evaluate the 6 core SOC defense pillars." />
          )}
        </section>
      )}

      {/* 4. THREAT GRAPH VIEW */}
      {view === "graph" && (
        <section className="workspace">
          <div className="eyebrow">CORRELATION TOPOLOGY</div>
          <h1>Interactive Threat Graph</h1>
          <p className="lede">
            Visualizes relational links between targets, host domains, resolved IPs, autonomous routing networks, and MITRE ATT&CK tactics.
          </p>

          <div className="command" style={{ margin: "20px 0" }}>
            <input
              type="text"
              placeholder="Enter target indicator (e.g., malicious-site.com or 185.220.101.5)..."
              defaultValue={activeTarget || ""}
              id="graphInput"
            />
            <button
              onClick={() => {
                const val = (document.getElementById("graphInput") as HTMLInputElement)?.value;
                if (val) runThreatGraph(val, detect(val));
                else toast.error("Enter an indicator");
              }}
              disabled={busy}
            >
              Build Graph
            </button>
          </div>

          {graphData ? (
            <ThreatGraphCanvas data={graphData} />
          ) : (
            <EmptyState text="Enter an indicator above to render its correlation graph topology." />
          )}
        </section>
      )}

      {/* 5. DNS & EMAIL SPOOF AUDITOR VIEW */}
      {view === "dns" && (
        <section className="workspace">
          <div className="eyebrow">INFRASTRUCTURE POSTURE</div>
          <h1>Email Spoofing & DNS Audit</h1>
          <p className="lede">
            Validates SPF, DMARC policies, MX records, and queries public Certificate Transparency (CT) logs for hidden subdomains.
          </p>

          <div className="command" style={{ margin: "20px 0" }}>
            <input
              type="text"
              placeholder="Enter domain to audit (e.g., paypal.com, internal-target.org)..."
              defaultValue={activeTarget ? activeTarget.replace(/https?:\/\//, "").split("/")[0] : ""}
              id="dnsInput"
            />
            <button
              onClick={() => {
                const val = (document.getElementById("dnsInput") as HTMLInputElement)?.value;
                if (val) runDnsAudit(val);
                else toast.error("Enter a domain name");
              }}
              disabled={busy}
            >
              Audit Domain
            </button>
          </div>

          {dnsData ? (
            <DnsAuditDetails data={dnsData} />
          ) : (
            <EmptyState text="Enter a domain above to audit its SPF, DMARC, and Certificate Transparency profile." />
          )}
        </section>
      )}

      {/* 6. SOAR DEFENSES VIEW */}
      {view === "soar" && (
        <section className="workspace">
          <div className="eyebrow">AUTOMATED MITIGATION (SOAR)</div>
          <h1>Incident Response Playbooks</h1>
          <p className="lede">
            Instantly generates ready-to-deploy firewall rules (iptables, UFW, Windows Firewall, Cisco ASA), Suricata/Snort signatures, and DNS sinkholes.
          </p>

          <div className="command" style={{ margin: "20px 0" }}>
            <input
              type="text"
              placeholder="Enter indicator (IP, domain, or hash) to generate mitigations..."
              defaultValue={activeTarget || ""}
              id="soarInput"
            />
            <button
              onClick={() => {
                const val = (document.getElementById("soarInput") as HTMLInputElement)?.value;
                if (val) runSoarPlaybook(val);
                else toast.error("Enter an indicator");
              }}
              disabled={busy}
            >
              Generate Playbook
            </button>
          </div>

          {soarData ? (
            <SoarPlaybookDetails data={soarData} />
          ) : (
            <EmptyState text="Enter an indicator to generate automated defensive mitigation rules." />
          )}
        </section>
      )}

      {/* 7. HISTORY & AUDIT REPORT VIEW */}
      {view === "history" && (
        <section className="workspace">
          <div className="eyebrow">LOCAL INVESTIGATION TRAIL</div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
            <h1>Audit Log & Reports</h1>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="primaryBtn"
                onClick={() => window.print()}
                style={{ background: "#243a46", color: "#9ed9ed", border: "1px solid var(--line)" }}
              >
                ⎙ Print / Save PDF
              </button>
              <button
                className="primaryBtn"
                onClick={() => {
                  const blob = new Blob([JSON.stringify(history, null, 2)], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `crie-audit-trail-${new Date().toISOString().slice(0, 10)}.json`;
                  a.click();
                  toast.success("Audit trail exported");
                }}
              >
                Export JSON
              </button>
            </div>
          </div>

          <div className="filters">
            {["all", "low", "medium", "high", "critical"].map((item) => (
              <button key={item} className={filter === item ? "active" : ""} onClick={() => setFilter(item)}>
                {item}
              </button>
            ))}
          </div>

          {visibleHistory.length ? (
            <div className="history">
              {visibleHistory.map((item) => (
                <button
                  className="historyRow"
                  key={item.id}
                  onClick={() => {
                    setResult(item.result);
                    setActiveTarget(item.input);
                    setView("detail");
                  }}
                >
                  <RiskDot level={risk(item.result)} />
                  <span>
                    <b>{item.input}</b>
                    <small>{item.kind} · {new Date(item.at).toLocaleString()}</small>
                  </span>
                  <strong>{score(item.result)}/100</strong>
                </button>
              ))}
            </div>
          ) : (
            <EmptyState text="No investigation records match this filter. Run scans to build your trail." />
          )}
        </section>
      )}

      {/* 8. DETAIL VIEW */}
      {view === "detail" && result && (
        <section className="workspace detail">
          <button className="back" onClick={() => setView("scan")}>← Back to Workbench</button>
          <ResultCard
            result={result}
            onGraph={() => runThreatGraph(activeTarget || String(result.input || "target"), detect(activeTarget || "domain"))}
            onSoar={() => runSoarPlaybook(activeTarget || String(result.input || "target"))}
            onFusion={() => runCyberFusion(activeTarget || String(result.input || "target"))}
          />
          <IntelDetail result={result} />
        </section>
      )}
    </main>
  );
}

// ─────────────────────────────────────────────
// COMPONENT: Result Card
// ─────────────────────────────────────────────
function ResultCard({
  result,
  onDetail,
  onGraph,
  onSoar,
  onFusion,
}: {
  result: ScanResult;
  onDetail?: () => void;
  onGraph?: () => void;
  onSoar?: () => void;
  onFusion?: () => void;
}) {
  const value = score(result);
  const level = risk(result);
  const sources = (result.ioc_intelligence as Record<string, unknown>)?.results as unknown[] | undefined;

  return (
    <section className="result">
      <div className={`horizon ${level}`} style={{ "--score": `${value}%` } as React.CSSProperties}>
        <div className="arc">
          <b>{value}</b>
          <span>/100</span>
        </div>
        <strong>{level}</strong>
        <small>risk verdict</small>
      </div>

      <div className="summary">
        <div className="eyebrow">VERDICT SUMMARY</div>
        <h2>{level === "critical" || level === "high" ? "High Risk Signals Identified" : level === "medium" ? "Suspicious Indicators Found" : "Clean / Low Risk"}</h2>
        <p>{action(level)}</p>
        <div className="chips">
          <span>{result.input ? String(result.input).slice(0, 32) : "indicator analyzed"}</span>
          <span>{sources?.length ?? 0} IOC records</span>
        </div>

        <div className="quickActions">
          {onDetail && <button onClick={onDetail}>Full Intel Report →</button>}
          {onGraph && <button onClick={onGraph}>View in Threat Graph ☍</button>}
          {onSoar && <button onClick={onSoar}>Generate Defense Playbook 🛡</button>}
          {onFusion && <button onClick={onFusion}>SOC Fusion Matrix ◈</button>}
        </div>
      </div>

      <div className="evidence">
        <h3>Key Evidence</h3>
        {Array.isArray(result.signals) && result.signals.length ? (
          result.signals.slice(0, 4).map((signal: any, index: number) => (
            <p key={index}>
              <RiskDot level={level} />
              {signal.detail ?? signal.name ?? signal.signal}
            </p>
          ))
        ) : (
          <p>
            <RiskDot level={level} />
            Live reputation feeds and local heuristics verified.
          </p>
        )}
      </div>
    </section>
  );
}

function RiskDot({ level }: { level: string }) {
  return <i className={`dot ${level}`} />;
}

// ─────────────────────────────────────────────
// COMPONENT: File Analysis Deep Details
// ─────────────────────────────────────────────
function FileAnalysisDetails({ data, onSoar }: { data: any; onSoar?: () => void }) {
  const entropy = Number(data.entropy || 0);
  const entropyPct = Math.min(100, (entropy / 8.0) * 100);
  const entropyColor = entropy >= 7.0 ? "danger" : entropy >= 6.0 ? "warn" : "safe";

  return (
    <div style={{ marginTop: 24, display: "grid", gap: 18 }}>
      {/* File Stats Card */}
      <div className="cardBox">
        <div className="targetTop">
          <div>
            <div className="eyebrow">SAMPLE TELEMETRY</div>
            <h2>{data.filename}</h2>
          </div>
          <span className={`verdictBadge ${data.risk_level}`}>{data.risk_level} risk</span>
        </div>

        <div className="targetFacts">
          <div><small>File Size</small><b>{data.size_bytes} bytes</b></div>
          <div><small>SHA256</small><b title={data.sha256}>{data.sha256 ? `${data.sha256.slice(0, 16)}...` : "N/A"}</b></div>
          <div><small>MD5</small><b>{data.md5}</b></div>
          <div><small>Risk Score</small><b>{data.risk_score} / 100</b></div>
        </div>

        {/* Entropy Gauge */}
        <div className="entropyGauge">
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ font: "12px 'JetBrains Mono'", color: "var(--muted)" }}>SHANNON ENTROPY ASSESSMENT</span>
            <b style={{ color: entropy >= 7.0 ? "var(--danger)" : "var(--safe)" }}>{entropy} / 8.0</b>
          </div>
          <div className="entropyBar">
            <div className={`entropyFill ${entropyColor}`} style={{ width: `${entropyPct}%` }} />
          </div>
          <small style={{ color: "var(--muted)" }}>{data.entropy_assessment}</small>
        </div>

        {onSoar && (
          <button className="primaryBtn" onClick={onSoar} style={{ marginTop: 10 }}>
            Generate Mitigation Playbook for this Hash →
          </button>
        )}
      </div>

      {/* PE Metadata & Sections */}
      {data.pe_metadata?.is_pe && (
        <div className="cardBox">
          <div className="eyebrow">PORTABLE EXECUTABLE (PE) HEADERS</div>
          <h3>Architecture & Section Layout</h3>
          <p style={{ color: "var(--muted)", fontSize: 13 }}>
            Architecture: <b>{data.pe_metadata.machine}</b> · Packed Status: <b>{data.pe_metadata.is_packed ? "PACKED / CRYPTED" : "STANDARD"}</b> · Compile Date: <b>{data.pe_metadata.timestamp_utc}</b>
          </p>

          {data.pe_metadata.sections?.length > 0 && (
            <table className="peTable">
              <thead>
                <tr>
                  <th>Section</th>
                  <th>Virtual Size</th>
                  <th>Raw Size</th>
                  <th>Entropy</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {data.pe_metadata.sections.map((sec: any) => (
                  <tr key={sec.index}>
                    <td><code>{sec.name}</code></td>
                    <td>{sec.virtual_size}</td>
                    <td>{sec.raw_size}</td>
                    <td>{sec.entropy}</td>
                    <td>
                      <span className={`verdictBadge ${sec.suspicious_entropy ? "critical" : "safe"}`}>
                        {sec.suspicious_entropy ? "Suspicious Entropy" : "Normal"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Suspicious APIs */}
      {data.detected_apis && Object.keys(data.detected_apis).length > 0 && (
        <div className="cardBox">
          <div className="eyebrow">MITRE ATT&CK ALIGNED APIS</div>
          <h3>High-Risk Windows API Imports</h3>
          {Object.entries(data.detected_apis).map(([cat, apis]: [string, any]) => (
            <div key={cat} style={{ marginTop: 12 }}>
              <small style={{ textTransform: "uppercase", color: "var(--accent)", font: "11px 'JetBrains Mono'" }}>{cat.replace(/_/g, " ")}</small>
              <div className="apiTagGrid">
                {apis.map((apiName: string) => (
                  <span className="apiTag" key={apiName}>{apiName}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Auto-Generated YARA Rule */}
      {data.yara_rule && (
        <div className="cardBox">
          <div className="codeBlockHeader">
            <span>AUTOMATED YARA DETECTION SIGNATURE</span>
            <button
              className="copyMiniBtn"
              onClick={() => {
                navigator.clipboard.writeText(data.yara_rule);
                toast.success("YARA rule copied to clipboard");
              }}
            >
              Copy YARA Rule
            </button>
          </div>
          <div className="codeBlockContainer">
            <pre>{data.yara_rule}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────
// COMPONENT: Cyber Fusion SOC Details
// ─────────────────────────────────────────────
function CyberFusionDetails({ data }: { data: any }) {
  const modules = data.modules || {};
  const entries = Object.entries(modules);

  return (
    <div style={{ marginTop: 20 }}>
      <div className="cardBox">
        <div className="targetTop">
          <div>
            <div className="eyebrow">COMPOSITE EVALUATION</div>
            <h2>SOC Risk Fusion Overview</h2>
          </div>
          <span className="verdictBadge medium">6 Pillars Active</span>
        </div>
        <p style={{ color: "var(--muted)", margin: "8px 0 0" }}>
          Target: <code>{data.target || "Composite Surface"}</code> · Evaluated at {new Date(data.generated_at).toLocaleString()}
        </p>

        <div className="fusionGrid">
          {entries.map(([key, mod]: [string, any]) => {
            const modScore = Number(mod.score || 0);
            const statusColor = modScore >= 70 ? "var(--danger)" : modScore >= 40 ? "var(--warn)" : "var(--safe)";
            return (
              <div className="fusionCard" key={key}>
                <div className="fusionCardHeader">
                  <h3>{key.replace(/_/g, " ").toUpperCase()}</h3>
                  <span className={`verdictBadge ${mod.state === "critical" ? "critical" : mod.state === "elevated" ? "medium" : "safe"}`}>
                    {mod.state}
                  </span>
                </div>
                <div className="fusionScore" style={{ color: statusColor }}>
                  {modScore} <small style={{ fontSize: 13, color: "var(--muted)" }}>/ 100</small>
                </div>
                <div className="fusionBar">
                  <div className="fusionBarFill" style={{ width: `${modScore}%`, background: statusColor }} />
                </div>
                <p style={{ color: "var(--muted)", fontSize: 12, margin: "10px 0 0" }}>{mod.headline}</p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// COMPONENT: Interactive Threat Graph Canvas
// ─────────────────────────────────────────────
function ThreatGraphCanvas({ data }: { data: any }) {
  const [zoom, setZoom] = useState(1);
  const [selectedNode, setSelectedNode] = useState<any>(null);

  const nodes = data.nodes || [];
  const edges = data.edges || [];

  // Compute circular layout coordinates
  const centerX = 440;
  const centerY = 260;
  const radius = 180;

  const nodePositions = useMemo(() => {
    const posMap: Record<string, { x: number; y: number }> = {};
    const nonRoot = nodes.filter((n: any) => !n.meta?.is_root);

    // Root node in center
    const rootNode = nodes.find((n: any) => n.meta?.is_root) || nodes[0];
    if (rootNode) posMap[rootNode.id] = { x: centerX, y: centerY };

    nonRoot.forEach((node: any, idx: number) => {
      const angle = (idx / Math.max(1, nonRoot.length)) * 2 * Math.PI;
      posMap[node.id] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
      };
    });
    return posMap;
  }, [nodes]);

  return (
    <div style={{ marginTop: 20 }}>
      <div className="graphContainer">
        <div className="graphControls">
          <button onClick={() => setZoom((z) => Math.min(2.0, z + 0.15))}>+</button>
          <button onClick={() => setZoom((z) => Math.max(0.5, z - 0.15))}>−</button>
          <button onClick={() => setZoom(1)}>↺</button>
        </div>

        <svg width="100%" height="100%" viewBox="0 0 880 520" style={{ transform: `scale(${zoom})`, transformOrigin: "center" }}>
          {/* Edges */}
          {edges.map((edge: any) => {
            const src = nodePositions[edge.source] || { x: centerX, y: centerY };
            const dst = nodePositions[edge.target] || { x: centerX, y: centerY };
            return (
              <g key={edge.id}>
                <line x1={src.x} y1={src.y} x2={dst.x} y2={dst.y} stroke="#2a4555" strokeWidth="2" strokeDasharray="4 2" />
                <text
                  x={(src.x + dst.x) / 2}
                  y={(src.y + dst.y) / 2 - 6}
                  fill="#73909e"
                  fontSize="10"
                  fontFamily="JetBrains Mono"
                  textAnchor="middle"
                >
                  {edge.label}
                </text>
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((node: any) => {
            const pos = nodePositions[node.id] || { x: centerX, y: centerY };
            const isSelected = selectedNode?.id === node.id;
            const nodeColor =
              node.risk === "critical"
                ? "#f05d5e"
                : node.risk === "high"
                ? "#ff826b"
                : node.risk === "medium"
                ? "#f0b44d"
                : "#43d19e";

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() => setSelectedNode(node)}
                style={{ cursor: "pointer" }}
              >
                <circle
                  r={node.meta?.is_root ? 28 : 20}
                  fill="#111d25"
                  stroke={nodeColor}
                  strokeWidth={isSelected ? 4 : 2}
                  filter="drop-shadow(0 0 8px rgba(0,0,0,0.6))"
                />
                <circle r={node.meta?.is_root ? 10 : 6} fill={nodeColor} />
                <text
                  y={node.meta?.is_root ? 42 : 32}
                  fill="#eaf2f8"
                  fontSize="11"
                  fontFamily="Space Grotesk"
                  fontWeight="600"
                  textAnchor="middle"
                >
                  {String(node.label).slice(0, 20)}
                </text>
                <text
                  y={node.meta?.is_root ? 54 : 44}
                  fill="#8ca2ad"
                  fontSize="9"
                  fontFamily="JetBrains Mono"
                  textAnchor="middle"
                >
                  {node.type}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="cardBox" style={{ marginTop: 14 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <small style={{ color: "var(--muted)", textTransform: "uppercase", font: "10px 'JetBrains Mono'" }}>SELECTED TOPOLOGY ENTITY</small>
              <h3 style={{ margin: "4px 0 0" }}>{selectedNode.label}</h3>
            </div>
            <span className={`verdictBadge ${selectedNode.risk}`}>{selectedNode.risk} risk</span>
          </div>
          <p style={{ color: "var(--muted)", fontSize: 13, margin: "8px 0 0" }}>
            Type: <code>{selectedNode.type}</code> · Node ID: <code>{selectedNode.id}</code>
          </p>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────
// COMPONENT: DNS & Email Spoof Auditor Details
// ─────────────────────────────────────────────
function DnsAuditDetails({ data }: { data: any }) {
  const isVulnerable = data.email_spoof_risk_score >= 40;

  return (
    <div style={{ marginTop: 24, display: "grid", gap: 18 }}>
      <div className="cardBox">
        <div className="targetTop">
          <div>
            <div className="eyebrow">EMAIL AUTHENTICATION AUDIT</div>
            <h2>{data.domain}</h2>
          </div>
          <span className={`verdictBadge ${isVulnerable ? "critical" : "safe"}`}>{data.verdict}</span>
        </div>

        <div className="targetFacts">
          <div><small>Resolved IP</small><b>{data.ip || "Unresolved"}</b></div>
          <div><small>Spoof Vulnerability</small><b>{data.email_spoof_risk_score} / 100</b></div>
          <div><small>DMARC Policy</small><b>{data.dmarc?.policy || "None"}</b></div>
          <div><small>SPF Policy</small><b>{data.spf?.policy || "None"}</b></div>
        </div>

        {/* Findings */}
        <div style={{ marginTop: 20 }}>
          <div className="eyebrow">AUDITOR EVALUATION FINDINGS</div>
          {data.findings?.map((f: any, idx: number) => (
            <div
              key={idx}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                marginTop: 8,
                padding: "8px 12px",
                borderRadius: 6,
                background: "#111d25",
                border: "1px solid #203542",
                fontSize: 13,
              }}
            >
              <span className={`verdictBadge ${f.status === "CRITICAL" ? "critical" : f.status === "HIGH" ? "critical" : f.status === "WARNING" ? "medium" : "safe"}`}>
                {f.status}
              </span>
              <span>{f.message}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Discovered Subdomains via Certificate Transparency */}
      <div className="cardBox">
        <div className="eyebrow">CERTIFICATE TRANSPARENCY ENUMERATION</div>
        <h3>Discovered Subdomains ({data.subdomain_count})</h3>
        <p style={{ color: "var(--muted)", fontSize: 13 }}>Public certificates logged for this infrastructure on crt.sh:</p>

        {data.subdomains_discovered?.length > 0 ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 8, marginTop: 12 }}>
            {data.subdomains_discovered.map((sub: string) => (
              <div
                key={sub}
                style={{
                  padding: "8px 10px",
                  background: "#101b22",
                  border: "1px solid #233744",
                  borderRadius: 6,
                  font: "12px 'JetBrains Mono'",
                  color: "#9ec5d6",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {sub}
              </div>
            ))}
          </div>
        ) : (
          <p style={{ color: "var(--muted)", fontSize: 13 }}>No active subdomains found in public CT log buffer.</p>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// COMPONENT: SOAR Defenses & Playbooks
// ─────────────────────────────────────────────
function SoarPlaybookDetails({ data }: { data: any }) {
  const [activeTab, setActiveTab] = useState<string>("iptables");
  const rules = data.rules || {};

  return (
    <div style={{ marginTop: 24 }}>
      <div className="cardBox">
        <div className="targetTop">
          <div>
            <div className="eyebrow">AUTOMATED RESPONSE PLAYBOOK</div>
            <h2>{data.title}</h2>
          </div>
          <span className="verdictBadge safe">Rules Active</span>
        </div>

        {/* Tab Selection */}
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "18px 0" }}>
          {[
            { id: "iptables", label: "Linux iptables" },
            { id: "ufw", label: "Linux UFW" },
            { id: "windows_firewall", label: "Windows Firewall" },
            { id: "cisco_asa", label: "Cisco ASA ACL" },
            { id: "suricata", label: "Suricata / Snort" },
            { id: "dns_sinkhole", label: "Pi-hole / Sinkhole" },
            { id: "yara", label: "YARA Hashes" },
          ].map((tab) => (
            <button
              key={tab.id}
              className={`tabBtn ${activeTab === tab.id ? "active" : ""}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Rule Code Block */}
        <div className="codeBlockContainer">
          <div className="codeBlockHeader">
            <span>SYNTAX: {activeTab.toUpperCase()}</span>
            <button
              className="copyMiniBtn"
              onClick={() => {
                navigator.clipboard.writeText(rules[activeTab] || "");
                toast.success(`Copied ${activeTab} playbook rules`);
              }}
            >
              Copy Playbook
            </button>
          </div>
          <pre>{rules[activeTab] || "# No rules generated for this category"}</pre>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// COMPONENT: Intel Detail (Legacy & Comprehensive)
// ─────────────────────────────────────────────
function IntelDetail({ result }: { result: ScanResult }) {
  const feeds = (result.feeds ?? {}) as Record<string, any>;
  const entries = Object.entries(feeds);
  const level = risk(result);
  const target = String(result.domain ?? result.input ?? "Scanned target");
  const scannedAt = result.scanned_at ? new Date(String(result.scanned_at)).toLocaleString() : "Just now";

  return (
    <div className="intelDetail">
      <section className="targetCard">
        <div className="targetTop">
          <div>
            <div className="eyebrow">TARGET PROFILE</div>
            <h2 title={target}>{target}</h2>
          </div>
          <span className={`verdictBadge ${level}`}>{level} risk</span>
        </div>
        <div className="targetFacts">
          <div><small>Target type</small><b>{result.domain ? "Domain / URL" : "Indicator"}</b></div>
          <div><small>Resolved address</small><b>{String(result.ip ?? "Not resolved")}</b></div>
          <div><small>Scan time</small><b>{scannedAt}</b></div>
          <div><small>Confidence score</small><b>{score(result)} <em>/ 100</em></b></div>
        </div>
      </section>

      <section className="providerPanel">
        <div className="sectionTitle">
          <div>
            <div className="eyebrow">SOURCE VERIFICATION</div>
            <h2>Reputation checks</h2>
            <p>Independent provider results for this indicator.</p>
          </div>
          <span className="sourceCount">{entries.length} {entries.length === 1 ? "source" : "sources"}</span>
        </div>
        {entries.length ? (
          <div className="providers">
            {entries.map(([name, feed]) => {
              const meta = providerMeta(name, feed);
              return (
                <article key={name} className={meta.flagged ? "flagged" : ""}>
                  <div className="providerIcon">{meta.label.slice(0, 1)}</div>
                  <div className="providerInfo">
                    <small>{meta.label}</small>
                    <b>{meta.flagged ? "Signal detected" : meta.configured ? "No detection" : "Not configured"}</b>
                    <p>{meta.metric}</p>
                  </div>
                  <span className={`providerState ${meta.flagged ? "flagged" : meta.configured ? "clear" : "off"}`}>
                    {meta.flagged ? "Review" : meta.configured ? "Clear" : "Offline"}
                  </span>
                </article>
              );
            })}
          </div>
        ) : (
          <div style={{ marginTop: 18, color: "var(--muted)", fontSize: 13 }}>
            No third-party reputation feeds returned data for this scan. The score reflects local heuristic evaluation.
          </div>
        )}
      </section>

      <details className="raw">
        <summary>
          <span>Raw Technical Telemetry</span>
          <small>JSON export</small>
        </summary>
        <pre>{JSON.stringify(result, null, 2)}</pre>
      </details>
    </div>
  );
}

function providerMeta(name: string, feed: any) {
  const label = name === "otx" ? "AlienVault OTX" : name === "virustotal" ? "VirusTotal" : name === "abuseipdb" ? "AbuseIPDB" : name;
  const configured = feed?.enabled !== false;
  const flagged = Boolean(feed?.listed) || Number(feed?.malicious ?? feed?.malicious_votes ?? 0) > 0 || Number(feed?.abuseConfidence ?? feed?.abuse_confidence ?? 0) >= 25;
  const metric =
    name === "virustotal"
      ? `${feed?.malicious ?? feed?.malicious_votes ?? 0} malicious detections`
      : name === "otx"
      ? `${feed?.pulseCount ?? feed?.pulse_count ?? 0} threat pulses`
      : `${feed?.abuseConfidence ?? feed?.abuse_confidence ?? 0}% abuse confidence`;
  return { label, configured, flagged, metric };
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="empty">
      <span>⌁</span>
      <p>{text}</p>
    </div>
  );
}

function FileDropPanel({ onFile, busy }: { onFile: (file: File) => void; busy: boolean }) {
  const drop = useDropzone({
    multiple: false,
    disabled: busy,
    onDropAccepted: (files) => onFile(files[0]),
    onDropRejected: () => toast.error("Choose a valid file under upload limits."),
  });

  return (
    <div {...drop.getRootProps({ className: `dropzone ${drop.isDragActive ? "over" : ""}` })}>
      <input {...drop.getInputProps()} />
      <span>↥</span>
      <h2>{busy ? "Analyzing binary telemetry…" : drop.isDragActive ? "Drop to scan" : "Drop an executable, script, or document"}</h2>
      <p>Checks PE headers, section entropy, suspicious APIs, and generates YARA rules</p>
      <button type="button" className="primaryBtn" style={{ marginTop: 12 }}>Choose File</button>
    </div>
  );
}
