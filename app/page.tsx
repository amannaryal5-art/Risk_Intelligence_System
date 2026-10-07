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

const scanSchema = z.object({ target: z.string().trim().min(2, "Please enter something to check — a website link, email address, or suspicious text.") });

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

/** Plain-English action advice based on risk level */
function action(level: string) {
  return level === "critical" || level === "high"
    ? "⚠️ This looks dangerous. Do NOT open, click, or download it. Tell your IT team right away, or simply delete it."
    : level === "medium"
    ? "🟡 Something seems a bit off. Be careful — double-check where this came from before trusting it."
    : "✅ Nothing suspicious was found. Still be cautious — when in doubt, ask someone you trust.";
}

/** Human-friendly label for what kind of thing was detected */
function kindLabel(kind: string) {
  switch (kind) {
    case "url": return "Website link";
    case "domain": return "Website name";
    case "ip": return "Server address (IP)";
    case "email": return "Email address";
    case "hash": return "File fingerprint";
    case "text": return "Suspicious message";
    default: return kind;
  }
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

  async function submitScan({ target }: z.infer<typeof scanSchema>) {
    const kind = detect(target);
    setBusy(true);
    setActiveTarget(target);
    const toastId = toast.loading("Checking this for you — please wait…");
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
      toast.success("Check complete — see your results below", { id: toastId });
      remember(target, kind, data);
      setView("scan");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Something went wrong. Please try again.", { id: toastId });
    } finally {
      setBusy(false);
    }
  }

  async function fileScan(file: File) {
    setBusy(true);
    const toastId = toast.loading("Examining the file for hidden dangers…");
    try {
      const buffer = await file.arrayBuffer();
      const base64Content = toBase64(new Uint8Array(buffer));
      const data = await api<any>("/api/v1/malware/deep-analysis", {
        method: "POST",
        body: JSON.stringify({ filename: file.name, content_base64: base64Content }),
      });
      toast.success("File check complete", { id: toastId });
      setFileAnalysis(data);
      remember(file.name, "file", data);
      setView("file");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not analyze the file. Please try again.", { id: toastId });
    } finally {
      setBusy(false);
    }
  }

  async function runCyberFusion(target: string) {
    setBusy(true);
    const toastId = toast.loading("Running a full 360° risk check — this takes a moment…");
    try {
      const isUrl = target.startsWith("http://") || target.startsWith("https://") || target.includes(".");
      const payload = isUrl ? { website_url: target } : { text: target };
      const data = await api<any>("/api/v1/cyber-fusion", { method: "POST", body: JSON.stringify(payload) });
      toast.success("Full risk overview ready", { id: toastId });
      setFusionData(data);
      setView("fusion");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Full risk check failed. Please try again.", { id: toastId });
    } finally {
      setBusy(false);
    }
  }

  async function runThreatGraph(target: string, kind = "domain") {
    setBusy(true);
    const toastId = toast.loading("Mapping out all the connections…");
    try {
      const data = await api<any>("/api/v1/threat-graph", {
        method: "POST",
        body: JSON.stringify({ target, kind, scan_data: result || undefined }),
      });
      toast.success("Connection map ready", { id: toastId });
      setGraphData(data);
      setView("graph");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not build the connection map.", { id: toastId });
    } finally {
      setBusy(false);
    }
  }

  async function runDnsAudit(domain: string) {
    setBusy(true);
    const toastId = toast.loading("Checking if fake emails can be sent from this domain…");
    try {
      const data = await api<any>("/api/v1/audit/domain-dns", {
        method: "POST",
        body: JSON.stringify({ domain }),
      });
      toast.success("Email safety check complete", { id: toastId });
      setDnsData(data);
      setView("dns");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Email safety check failed.", { id: toastId });
    } finally {
      setBusy(false);
    }
  }

  async function runSoarPlaybook(target: string) {
    setBusy(true);
    const toastId = toast.loading("Generating blocking instructions for your IT team…");
    try {
      const kind = detect(target);
      const payload: any = { title: `Block This Threat: ${target}` };
      if (kind === "ip") payload.ips = [target];
      else if (kind === "domain") payload.domains = [target];
      else if (kind === "url") payload.urls = [target];
      else if (kind === "hash") payload.hashes = [target];
      else payload.domains = [target];

      const data = await api<any>("/api/v1/soar/generate-rules", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      toast.success("Blocking instructions are ready", { id: toastId });
      setSoarData(data);
      setView("soar");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not generate blocking instructions.", { id: toastId });
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
            <b>SafeCheck</b>
            <small>Your Personal Cyber Safety Tool</small>
          </div>
        </div>

        <nav>
          {(
            [
              { id: "scan",    label: "🔍 Check Something" },
              { id: "file",    label: "📁 Check a File" },
              { id: "fusion",  label: "🛡 Full Risk Overview" },
              { id: "graph",   label: "🔗 See Connections" },
              { id: "dns",     label: "📧 Email Safety" },
              { id: "soar",    label: "🚫 Block This Threat" },
              { id: "history", label: "📋 My Past Checks" },
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
          <span>System Online</span>
        </div>
      </header>

      {/* ── WELCOME BANNER (only on scan tab with no result) ── */}
      {view === "scan" && !result && (
        <div style={{
          background: "linear-gradient(135deg, #0d2233 0%, #0b1a26 100%)",
          border: "1px solid #1e3a4d",
          borderRadius: 12,
          padding: "18px 24px",
          margin: "20px 24px 0",
          display: "flex",
          gap: 16,
          alignItems: "flex-start",
        }}>
          <span style={{ fontSize: 28 }}>👋</span>
          <div>
            <b style={{ color: "#9ed9ed", fontSize: 15 }}>New here? Here's what this tool does:</b>
            <p style={{ color: "#7a9bae", fontSize: 13, margin: "6px 0 0", lineHeight: 1.6 }}>
              SafeCheck helps you find out if a website, email, file, or message is <b>safe or dangerous</b> — before you open it or share any information.
              Just paste or type something suspicious and hit <b>Check Now</b>. No tech knowledge needed.
            </p>
          </div>
        </div>
      )}

      {/* 1. CHECK SOMETHING (SCAN) VIEW */}
      {view === "scan" && (
        <section className="workspace">
          <div className="eyebrow">STEP 1 OF 1 — PASTE ANYTHING SUSPICIOUS</div>
          <h1>Is this safe to open?</h1>
          <p className="lede">
            Paste a website link, email address, file fingerprint, server address, or a suspicious text message below.
            We'll check it against global security databases and tell you whether it's safe.
          </p>

          <form className="command" onSubmit={form.handleSubmit(submitScan)}>
            <textarea
              aria-label="Scan target"
              placeholder={
                "Examples:\n• https://suspicious-login-page.com\n• 185.220.101.5\n• user@scam-domain.xyz\n• Or paste a suspicious WhatsApp / email message here…"
              }
              {...form.register("target")}
            />
            <button disabled={busy}>{busy ? "Checking…" : "Check Now →"}</button>
          </form>

          {form.formState.errors.target && <p className="error">{form.formState.errors.target.message}</p>}
          {form.watch("target").trim().length > 1 && (
            <p className="hint">
              We detected this as: <b>{kindLabel(currentKind)}</b> — we'll use the right method to check it.
            </p>
          )}

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
            <EmptyState text="Enter something above and click 'Check Now' to get your safety report." />
          )}
        </section>
      )}

      {/* 2. CHECK A FILE VIEW */}
      {view === "file" && (
        <section className="workspace">
          <div className="eyebrow">FILE SAFETY CHECK</div>
          <h1>Is this file safe?</h1>
          <p className="lede">
            Drop a file you received (like a .exe, .dll, or document with macros) and we'll examine it for hidden dangers —
            viruses, ransomware, or other malicious code — <b>without running it</b>.
          </p>

          {/* Plain-language info box */}
          <div style={{
            background: "#0d2233",
            border: "1px solid #1e3a4d",
            borderRadius: 10,
            padding: "14px 18px",
            marginBottom: 20,
            fontSize: 13,
            color: "#7a9bae",
            lineHeight: 1.7,
          }}>
            <b style={{ color: "#9ed9ed" }}>ℹ️ What we check:</b>
            <ul style={{ margin: "8px 0 0", paddingLeft: 20 }}>
              <li><b>Hidden code patterns</b> — signs of viruses or ransomware inside the file</li>
              <li><b>How scrambled the file is</b> — malware often tries to hide itself by being heavily encoded</li>
              <li><b>Dangerous capabilities</b> — functions the file can use that are common in malware (e.g., keylogging, screen capture)</li>
              <li><b>Detection rule</b> — a snippet your IT team can use to find similar threats on other computers</li>
            </ul>
          </div>

          <FileDropPanel onFile={fileScan} busy={busy} />

          {fileAnalysis && <FileAnalysisDetails data={fileAnalysis} onSoar={() => runSoarPlaybook(fileAnalysis.sha256)} />}
        </section>
      )}

      {/* 3. FULL RISK OVERVIEW (FUSION) VIEW */}
      {view === "fusion" && (
        <section className="workspace">
          <div className="eyebrow">FULL 360° RISK OVERVIEW</div>
          <h1>Complete risk picture</h1>
          <p className="lede">
            This runs <b>6 different types of checks</b> at once on a website or message, giving you a complete picture of how risky it is.
            Think of it as a full health report — not just one test, but many.
          </p>

          <div style={{
            background: "#0d2233",
            border: "1px solid #1e3a4d",
            borderRadius: 10,
            padding: "14px 18px",
            marginBottom: 16,
            fontSize: 13,
            color: "#7a9bae",
            lineHeight: 1.7,
          }}>
            <b style={{ color: "#9ed9ed" }}>📊 The 6 risk areas we check:</b>
            <ol style={{ margin: "8px 0 0", paddingLeft: 20 }}>
              <li><b>Threat reputation</b> — is this known to be dangerous?</li>
              <li><b>Attack surface</b> — how exposed is this target to hackers?</li>
              <li><b>Dark web activity</b> — has this shown up on criminal forums?</li>
              <li><b>Phishing risk</b> — is this trying to trick you into giving away info?</li>
              <li><b>Fake email risk</b> — can criminals send fake emails pretending to be from this domain?</li>
              <li><b>Security weaknesses</b> — known software vulnerabilities on this site</li>
            </ol>
          </div>

          <div className="command" style={{ margin: "20px 0" }}>
            <input
              type="text"
              placeholder="Enter a website name or suspicious message — e.g., paypal-support.net"
              defaultValue={activeTarget || ""}
              id="fusionInput"
            />
            <button
              onClick={() => {
                const val = (document.getElementById("fusionInput") as HTMLInputElement)?.value;
                if (val) runCyberFusion(val);
                else toast.error("Please enter a website name or message to check.");
              }}
              disabled={busy}
            >
              Run Full Check
            </button>
          </div>

          {fusionData ? (
            <CyberFusionDetails data={fusionData} />
          ) : (
            <EmptyState text="Enter a website or message above and click 'Run Full Check' to see the complete risk breakdown." />
          )}
        </section>
      )}

      {/* 4. SEE CONNECTIONS (THREAT GRAPH) VIEW */}
      {view === "graph" && (
        <section className="workspace">
          <div className="eyebrow">CONNECTION MAP</div>
          <h1>See how things are connected</h1>
          <p className="lede">
            This draws a visual map showing how a suspicious website, server, or address is linked to other dangerous things on the internet.
            Each circle (node) is an entity — lines connecting them show relationships.
          </p>

          <div style={{
            background: "#0d2233",
            border: "1px solid #1e3a4d",
            borderRadius: 10,
            padding: "14px 18px",
            marginBottom: 16,
            fontSize: 13,
            color: "#7a9bae",
          }}>
            <b style={{ color: "#9ed9ed" }}>🗺 How to read the map:</b>
            <div style={{ display: "flex", gap: 20, flexWrap: "wrap", marginTop: 10 }}>
              <span>🔴 <b>Red circle</b> = dangerous / critical</span>
              <span>🟠 <b>Orange circle</b> = high risk</span>
              <span>🟡 <b>Yellow circle</b> = medium risk</span>
              <span>🟢 <b>Green circle</b> = low risk / safe</span>
              <span>─── <b>Lines</b> = connected to each other</span>
            </div>
            <p style={{ marginTop: 10 }}>Click on any circle to see more details about it.</p>
          </div>

          <div className="command" style={{ margin: "20px 0" }}>
            <input
              type="text"
              placeholder="Enter a website or server address — e.g., fake-banking-site.com or 185.220.101.5"
              defaultValue={activeTarget || ""}
              id="graphInput"
            />
            <button
              onClick={() => {
                const val = (document.getElementById("graphInput") as HTMLInputElement)?.value;
                if (val) runThreatGraph(val, detect(val));
                else toast.error("Please enter a website or server address.");
              }}
              disabled={busy}
            >
              Show Connections
            </button>
          </div>

          {graphData ? (
            <ThreatGraphCanvas data={graphData} />
          ) : (
            <EmptyState text="Enter a website or server above to see its connection map." />
          )}
        </section>
      )}

      {/* 5. EMAIL SAFETY (DNS AUDIT) VIEW */}
      {view === "dns" && (
        <section className="workspace">
          <div className="eyebrow">EMAIL SAFETY CHECK</div>
          <h1>Can criminals fake emails from this website?</h1>
          <p className="lede">
            This checks whether a website has protection in place to <b>stop criminals from sending fake emails</b> that pretend to come from it.
            For example — can someone send you a fake "PayPal" or "your-bank.com" email even though they're not really PayPal?
          </p>

          <div style={{
            background: "#0d2233",
            border: "1px solid #1e3a4d",
            borderRadius: 10,
            padding: "14px 18px",
            marginBottom: 16,
            fontSize: 13,
            color: "#7a9bae",
            lineHeight: 1.7,
          }}>
            <b style={{ color: "#9ed9ed" }}>📧 What we check (in plain English):</b>
            <ul style={{ margin: "8px 0 0", paddingLeft: 20 }}>
              <li><b>Email protection (SPF)</b> — a list of approved servers allowed to send emails from this domain. No SPF = anyone can fake their emails.</li>
              <li><b>Anti-spoofing policy (DMARC)</b> — what happens when someone tries to send a fake email from this domain. "None" = criminals can freely impersonate them.</li>
              <li><b>Hidden subdomains</b> — other websites running under this domain that you might not know about (found using public SSL certificate records).</li>
            </ul>
          </div>

          <div className="command" style={{ margin: "20px 0" }}>
            <input
              type="text"
              placeholder="Enter a website name to check — e.g., paypal.com, your-bank.com, your-company.com"
              defaultValue={activeTarget ? activeTarget.replace(/https?:\/\//, "").split("/")[0] : ""}
              id="dnsInput"
            />
            <button
              onClick={() => {
                const val = (document.getElementById("dnsInput") as HTMLInputElement)?.value;
                if (val) runDnsAudit(val);
                else toast.error("Please enter a website name.");
              }}
              disabled={busy}
            >
              Check Email Safety
            </button>
          </div>

          {dnsData ? (
            <DnsAuditDetails data={dnsData} />
          ) : (
            <EmptyState text="Enter a website name above to check if fake emails can be sent from it." />
          )}
        </section>
      )}

      {/* 6. BLOCK THIS THREAT (SOAR) VIEW */}
      {view === "soar" && (
        <section className="workspace">
          <div className="eyebrow">READY-TO-USE BLOCKING INSTRUCTIONS</div>
          <h1>Block this threat on your systems</h1>
          <p className="lede">
            Enter something dangerous (a website, server address, or file fingerprint) and we'll generate
            <b> ready-made instructions</b> for your IT team to block it on different types of systems.
            Just copy the relevant section and hand it to your IT person.
          </p>

          <div style={{
            background: "#0d2233",
            border: "1px solid #1e3a4d",
            borderRadius: 10,
            padding: "14px 18px",
            marginBottom: 16,
            fontSize: 13,
            color: "#7a9bae",
            lineHeight: 1.7,
          }}>
            <b style={{ color: "#9ed9ed" }}>🚫 What gets generated (pick the right one for your setup):</b>
            <ul style={{ margin: "8px 0 0", paddingLeft: 20 }}>
              <li><b>Linux/Mac Firewall Block</b> — commands to block this on a Linux or Mac computer firewall</li>
              <li><b>Linux UFW Firewall</b> — another common Linux firewall tool</li>
              <li><b>Windows Firewall Block</b> — instructions for Windows computers</li>
              <li><b>Router/Enterprise Block (Cisco)</b> — for network engineers managing office routers</li>
              <li><b>Network Alarm Rules</b> — alerts that trigger when this threat is seen on your network (uses Suricata/Snort — security monitoring tools)</li>
              <li><b>DNS Block (Pi-hole / Home Router)</b> — block the domain at the DNS level, works like a router blocklist</li>
              <li><b>File Signature (YARA)</b> — a fingerprint rule so your security software can find similar dangerous files</li>
            </ul>
          </div>

          <div className="command" style={{ margin: "20px 0" }}>
            <input
              type="text"
              placeholder="Enter what to block — e.g., malware-site.com, 185.220.101.5, or a file hash"
              defaultValue={activeTarget || ""}
              id="soarInput"
            />
            <button
              onClick={() => {
                const val = (document.getElementById("soarInput") as HTMLInputElement)?.value;
                if (val) runSoarPlaybook(val);
                else toast.error("Please enter something to block.");
              }}
              disabled={busy}
            >
              Generate Block Instructions
            </button>
          </div>

          {soarData ? (
            <SoarPlaybookDetails data={soarData} />
          ) : (
            <EmptyState text="Enter something dangerous above and we'll generate blocking instructions for your IT team." />
          )}
        </section>
      )}

      {/* 7. MY PAST CHECKS (HISTORY) VIEW */}
      {view === "history" && (
        <section className="workspace">
          <div className="eyebrow">YOUR CHECK HISTORY</div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
            <h1>📋 My Past Checks</h1>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="primaryBtn"
                onClick={() => window.print()}
                style={{ background: "#243a46", color: "#9ed9ed", border: "1px solid var(--line)" }}
              >
                🖨 Print / Save as PDF
              </button>
              <button
                className="primaryBtn"
                onClick={() => {
                  const blob = new Blob([JSON.stringify(history, null, 2)], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `safecheck-history-${new Date().toISOString().slice(0, 10)}.json`;
                  a.click();
                  toast.success("Your check history has been downloaded.");
                }}
              >
                ⬇ Download Report
              </button>
            </div>
          </div>
          <p className="lede" style={{ marginTop: 8 }}>
            Every check you run is saved here so you can revisit it later. Nothing is sent to any server — it's stored only on your device.
          </p>

          <div className="filters">
            {[
              { id: "all", label: "All" },
              { id: "low", label: "✅ Safe" },
              { id: "medium", label: "🟡 Caution" },
              { id: "high", label: "🔴 High Risk" },
              { id: "critical", label: "💀 Critical" },
            ].map((item) => (
              <button key={item.id} className={filter === item.id ? "active" : ""} onClick={() => setFilter(item.id)}>
                {item.label}
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
                    <small>{kindLabel(item.kind)} · {new Date(item.at).toLocaleString()}</small>
                  </span>
                  <strong>{score(item.result)}/100</strong>
                </button>
              ))}
            </div>
          ) : (
            <EmptyState text="No checks match this filter yet. Run some checks to build your history." />
          )}
        </section>
      )}

      {/* 8. DETAIL VIEW */}
      {view === "detail" && result && (
        <section className="workspace detail">
          <button className="back" onClick={() => setView("scan")}>← Back to Check</button>
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

  const riskLabel =
    level === "critical" ? "CRITICAL — Dangerous"
    : level === "high" ? "HIGH RISK"
    : level === "medium" ? "CAUTION — Suspicious"
    : "SAFE — No Threats Found";

  return (
    <section className="result">
      <div className={`horizon ${level}`} style={{ "--score": `${value}%` } as React.CSSProperties}>
        <div className="arc">
          <b>{value}</b>
          <span>/100</span>
        </div>
        <strong>{riskLabel}</strong>
        <small>danger score</small>
      </div>

      <div className="summary">
        <div className="eyebrow">WHAT WE FOUND</div>
        <h2>
          {level === "critical" || level === "high"
            ? "⚠️ This looks dangerous"
            : level === "medium"
            ? "🟡 This seems suspicious"
            : "✅ Nothing suspicious found"}
        </h2>
        <p>{action(level)}</p>
        <div className="chips">
          <span>{result.input ? String(result.input).slice(0, 40) : "item analyzed"}</span>
          <span>Checked against {sources?.length ?? 0} security databases</span>
        </div>

        <div className="quickActions">
          {onDetail && <button onClick={onDetail}>📄 Full Report →</button>}
          {onGraph && <button onClick={onGraph}>🔗 See Connections ☍</button>}
          {onSoar && <button onClick={onSoar}>🚫 Get Blocking Instructions 🛡</button>}
          {onFusion && <button onClick={onFusion}>📊 Full Risk Overview ◈</button>}
        </div>
      </div>

      <div className="evidence">
        <h3>🔎 Why we think this</h3>
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
            Checked across live security databases and local detection patterns.
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

  // Plain-English entropy label
  const entropyMeaning =
    entropy >= 7.0
      ? "Very heavily hidden — this is a strong warning sign of malware"
      : entropy >= 6.0
      ? "Moderately scrambled — could indicate the file is packed or protected"
      : "Normal — the file doesn't appear to be hiding itself";

  return (
    <div style={{ marginTop: 24, display: "grid", gap: 18 }}>
      {/* File Stats Card */}
      <div className="cardBox">
        <div className="targetTop">
          <div>
            <div className="eyebrow">FILE DETAILS</div>
            <h2>{data.filename}</h2>
          </div>
          <span className={`verdictBadge ${data.risk_level}`}>{data.risk_level} risk</span>
        </div>

        <div className="targetFacts">
          <div><small>File Size</small><b>{data.size_bytes} bytes</b></div>
          <div><small>Unique Fingerprint (SHA256)</small><b title={data.sha256}>{data.sha256 ? `${data.sha256.slice(0, 16)}…` : "N/A"}</b></div>
          <div><small>Short Fingerprint (MD5)</small><b>{data.md5}</b></div>
          <div><small>Danger Score</small><b>{data.risk_score} / 100</b></div>
        </div>

        {/* Entropy Gauge — plain English */}
        <div className="entropyGauge">
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ font: "12px 'JetBrains Mono'", color: "var(--muted)" }}>
              HOW HIDDEN IS THIS FILE? (Obfuscation Level)
            </span>
            <b style={{ color: entropy >= 7.0 ? "var(--danger)" : "var(--safe)" }}>{entropy} / 8.0</b>
          </div>
          <div className="entropyBar">
            <div className={`entropyFill ${entropyColor}`} style={{ width: `${entropyPct}%` }} />
          </div>
          <small style={{ color: "var(--muted)" }}>{entropyMeaning}</small>
        </div>

        {onSoar && (
          <button className="primaryBtn" onClick={onSoar} style={{ marginTop: 10 }}>
            🚫 Generate Blocking Instructions for this File →
          </button>
        )}
      </div>

      {/* PE Metadata & Sections — plain English headers */}
      {data.pe_metadata?.is_pe && (
        <div className="cardBox">
          <div className="eyebrow">INSIDE THE FILE (STRUCTURE ANALYSIS)</div>
          <h3>How the file is built internally</h3>
          <p style={{ color: "var(--muted)", fontSize: 13 }}>
            Type: <b>{data.pe_metadata.machine}</b> (Windows program) ·
            Packed/Protected: <b>{data.pe_metadata.is_packed ? "YES — this file is deliberately hiding its contents ⚠️" : "No — appears normal"}</b> ·
            Created on: <b>{data.pe_metadata.timestamp_utc}</b>
          </p>

          {data.pe_metadata.sections?.length > 0 && (
            <>
              <p style={{ color: "var(--muted)", fontSize: 12, marginTop: 12 }}>
                Files are split into internal sections. High "obfuscation" in any section is suspicious.
              </p>
              <table className="peTable">
                <thead>
                  <tr>
                    <th>Section Name</th>
                    <th>Expected Size</th>
                    <th>Actual Size</th>
                    <th>Obfuscation Level</th>
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
                          {sec.suspicious_entropy ? "⚠️ Suspicious" : "✅ Normal"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}

      {/* Suspicious APIs — plain English */}
      {data.detected_apis && Object.keys(data.detected_apis).length > 0 && (
        <div className="cardBox">
          <div className="eyebrow">DANGEROUS CAPABILITIES FOUND IN THIS FILE</div>
          <h3>⚠️ What this file is able to do</h3>
          <p style={{ color: "var(--muted)", fontSize: 13, marginBottom: 10 }}>
            These are functions found inside the file that are commonly used by malware. Your IT team can use this list to understand the threat.
          </p>
          {Object.entries(data.detected_apis).map(([cat, apis]: [string, any]) => (
            <div key={cat} style={{ marginTop: 12 }}>
              <small style={{ textTransform: "uppercase", color: "var(--accent)", font: "11px 'JetBrains Mono'" }}>
                {cat.replace(/_/g, " ")}
              </small>
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
            <span>🔎 DETECTION RULE FOR IT TEAMS (YARA FORMAT)</span>
            <button
              className="copyMiniBtn"
              onClick={() => {
                navigator.clipboard.writeText(data.yara_rule);
                toast.success("Detection rule copied — share it with your IT team.");
              }}
            >
              Copy Rule
            </button>
          </div>
          <p style={{ color: "var(--muted)", fontSize: 12, padding: "8px 14px 0" }}>
            This is an auto-generated detection signature. Give it to your IT / security team — they can load it into antivirus or security monitoring tools to detect similar threats across your network.
          </p>
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

/** Plain-English names for each fusion module */
function fusionModuleLabel(key: string): string {
  const map: Record<string, string> = {
    threat_reputation: "🦠 Known Threat Reputation",
    attack_surface: "🌐 Attack Surface (How Exposed)",
    dark_web: "🕶 Dark Web Activity",
    phishing: "🎣 Phishing Risk (Trick Attempts)",
    email_spoof: "📧 Fake Email Risk",
    vulnerabilities: "🔓 Known Security Weaknesses",
  };
  return map[key] || key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function fusionStateLabel(state: string): string {
  if (state === "critical") return "🔴 Critical";
  if (state === "elevated") return "🟡 Elevated";
  if (state === "nominal" || state === "safe") return "🟢 Safe";
  return state;
}

function CyberFusionDetails({ data }: { data: any }) {
  const modules = data.modules || {};
  const entries = Object.entries(modules);

  return (
    <div style={{ marginTop: 20 }}>
      <div className="cardBox">
        <div className="targetTop">
          <div>
            <div className="eyebrow">COMPLETE RISK BREAKDOWN</div>
            <h2>Full Risk Overview</h2>
          </div>
          <span className="verdictBadge medium">6 Areas Checked</span>
        </div>
        <p style={{ color: "var(--muted)", margin: "8px 0 0" }}>
          Checked: <code>{data.target || "Composite Surface"}</code> · At {new Date(data.generated_at).toLocaleString()}
        </p>

        <div className="fusionGrid">
          {entries.map(([key, mod]: [string, any]) => {
            const modScore = Number(mod.score || 0);
            const statusColor = modScore >= 70 ? "var(--danger)" : modScore >= 40 ? "var(--warn)" : "var(--safe)";
            return (
              <div className="fusionCard" key={key}>
                <div className="fusionCardHeader">
                  <h3>{fusionModuleLabel(key)}</h3>
                  <span className={`verdictBadge ${mod.state === "critical" ? "critical" : mod.state === "elevated" ? "medium" : "safe"}`}>
                    {fusionStateLabel(mod.state)}
                  </span>
                </div>
                <div className="fusionScore" style={{ color: statusColor }}>
                  {modScore} <small style={{ fontSize: 13, color: "var(--muted)" }}>/ 100 risk</small>
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

  const centerX = 440;
  const centerY = 260;
  const radius = 180;

  const nodePositions = useMemo(() => {
    const posMap: Record<string, { x: number; y: number }> = {};
    const nonRoot = nodes.filter((n: any) => !n.meta?.is_root);

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
          <button onClick={() => setZoom((z) => Math.min(2.0, z + 0.15))}>＋ Zoom In</button>
          <button onClick={() => setZoom((z) => Math.max(0.5, z - 0.15))}>－ Zoom Out</button>
          <button onClick={() => setZoom(1)}>↺ Reset</button>
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
              <small style={{ color: "var(--muted)", textTransform: "uppercase", font: "10px 'JetBrains Mono'" }}>
                YOU CLICKED ON:
              </small>
              <h3 style={{ margin: "4px 0 0" }}>{selectedNode.label}</h3>
            </div>
            <span className={`verdictBadge ${selectedNode.risk}`}>{selectedNode.risk} risk</span>
          </div>
          <p style={{ color: "var(--muted)", fontSize: 13, margin: "8px 0 0" }}>
            Type: <code>{selectedNode.type}</code> · Internal ID: <code>{selectedNode.id}</code>
          </p>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────
// COMPONENT: DNS & Email Safety Audit Details
// ─────────────────────────────────────────────
function DnsAuditDetails({ data }: { data: any }) {
  const isVulnerable = data.email_spoof_risk_score >= 40;

  return (
    <div style={{ marginTop: 24, display: "grid", gap: 18 }}>
      <div className="cardBox">
        <div className="targetTop">
          <div>
            <div className="eyebrow">EMAIL SAFETY REPORT</div>
            <h2>{data.domain}</h2>
          </div>
          <span className={`verdictBadge ${isVulnerable ? "critical" : "safe"}`}>{data.verdict}</span>
        </div>

        <div className="targetFacts">
          <div><small>Server Address (IP)</small><b>{data.ip || "Not found"}</b></div>
          <div>
            <small>Fake Email Risk Score</small>
            <b style={{ color: isVulnerable ? "var(--danger)" : "var(--safe)" }}>
              {data.email_spoof_risk_score} / 100
              {isVulnerable ? " ⚠️ Vulnerable" : " ✅ Protected"}
            </b>
          </div>
          <div>
            <small>Anti-Spoofing Policy (DMARC)</small>
            <b>{data.dmarc?.policy || "None — not protected ⚠️"}</b>
          </div>
          <div>
            <small>Email Allowlist (SPF)</small>
            <b>{data.spf?.policy || "None — not protected ⚠️"}</b>
          </div>
        </div>

        {/* Plain-English finding explanation */}
        {isVulnerable && (
          <div style={{
            background: "#1f0d0d",
            border: "1px solid #5a1a1a",
            borderRadius: 8,
            padding: "12px 16px",
            marginTop: 16,
            fontSize: 13,
            color: "#e88",
          }}>
            ⚠️ <b>This website is not fully protected against fake emails.</b> Someone could send an email pretending to be from <b>{data.domain}</b> and it may pass spam filters. Be extra suspicious of any email that claims to be from this domain.
          </div>
        )}
        {!isVulnerable && (
          <div style={{
            background: "#0d1f14",
            border: "1px solid #1a5a2a",
            borderRadius: 8,
            padding: "12px 16px",
            marginTop: 16,
            fontSize: 13,
            color: "#8e8",
          }}>
            ✅ <b>This website has email protection in place.</b> It's harder for criminals to send fake emails pretending to be from <b>{data.domain}</b>.
          </div>
        )}

        {/* Findings */}
        <div style={{ marginTop: 20 }}>
          <div className="eyebrow">DETAILED FINDINGS</div>
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

      {/* Subdomains — plain English */}
      <div className="cardBox">
        <div className="eyebrow">OTHER WEBSITES UNDER THIS DOMAIN (Discovered via public SSL records)</div>
        <h3>Hidden Sub-sites Found: {data.subdomain_count}</h3>
        <p style={{ color: "var(--muted)", fontSize: 13 }}>
          These are sub-websites (like mail.example.com or login.example.com) that exist under <b>{data.domain}</b>.
          They were discovered using public SSL certificate records (crt.sh) — a technique also used by hackers to map targets.
        </p>

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
          <p style={{ color: "var(--muted)", fontSize: 13 }}>No sub-websites were found in public records.</p>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// COMPONENT: Block This Threat (SOAR) Playbooks
// ─────────────────────────────────────────────
function SoarPlaybookDetails({ data }: { data: any }) {
  const [activeTab, setActiveTab] = useState<string>("iptables");
  const rules = data.rules || {};

  const tabs = [
    { id: "iptables",        label: "🐧 Linux Firewall Block" },
    { id: "ufw",             label: "🐧 Linux UFW Firewall" },
    { id: "windows_firewall",label: "🪟 Windows Firewall Block" },
    { id: "cisco_asa",       label: "🔧 Office Router (Cisco)" },
    { id: "suricata",        label: "🚨 Network Alarm Rules" },
    { id: "dns_sinkhole",    label: "🌐 DNS Block (Pi-hole / Router)" },
    { id: "yara",            label: "📄 File Detection Signature" },
  ];

  const tabDescriptions: Record<string, string> = {
    iptables: "Commands for blocking this threat on a Linux server or firewall. Copy and run these in a Linux terminal.",
    ufw: "Commands for the UFW firewall tool on Ubuntu/Linux. Paste these into a terminal.",
    windows_firewall: "Instructions for blocking this threat on a Windows computer firewall. Copy and give to your IT team.",
    cisco_asa: "Rules for Cisco network firewalls used in offices and enterprises. For your network engineer.",
    suricata: "Network monitoring rules that will trigger an alert if this threat is seen passing through your network. Uses Suricata/Snort (security monitoring tools).",
    dns_sinkhole: "Block this domain at the DNS level — works with Pi-hole home blocklists or enterprise DNS filters. Prevents any device from connecting to it.",
    yara: "A file fingerprint rule that security tools can use to detect files matching this threat on any device.",
  };

  return (
    <div style={{ marginTop: 24 }}>
      <div className="cardBox">
        <div className="targetTop">
          <div>
            <div className="eyebrow">BLOCKING INSTRUCTIONS FOR YOUR IT TEAM</div>
            <h2>{data.title}</h2>
          </div>
          <span className="verdictBadge safe">Ready to Use</span>
        </div>

        <p style={{ color: "var(--muted)", fontSize: 13, margin: "10px 0 16px" }}>
          📋 Pick the tab that matches your system, copy the code, and give it to your IT team. Each section shows a different method to block this threat.
        </p>

        {/* Tab Selection */}
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "4px 0 18px" }}>
          {tabs.map((tab) => (
            <button
              key={tab.id}
              className={`tabBtn ${activeTab === tab.id ? "active" : ""}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab description */}
        <div style={{
          background: "#0d2233",
          border: "1px solid #1e3a4d",
          borderRadius: 8,
          padding: "10px 14px",
          marginBottom: 12,
          fontSize: 13,
          color: "#7a9bae",
        }}>
          ℹ️ {tabDescriptions[activeTab] || "Copy these instructions and share with your IT team."}
        </div>

        {/* Rule Code Block */}
        <div className="codeBlockContainer">
          <div className="codeBlockHeader">
            <span>BLOCKING COMMANDS — {tabs.find(t => t.id === activeTab)?.label}</span>
            <button
              className="copyMiniBtn"
              onClick={() => {
                navigator.clipboard.writeText(rules[activeTab] || "");
                toast.success("Copied! Share this with your IT team.");
              }}
            >
              📋 Copy Instructions
            </button>
          </div>
          <pre>{rules[activeTab] || "# No rules generated for this category"}</pre>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// COMPONENT: Intel Detail (Full Report)
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
            <div className="eyebrow">WHAT WAS CHECKED</div>
            <h2 title={target}>{target}</h2>
          </div>
          <span className={`verdictBadge ${level}`}>{level} risk</span>
        </div>
        <div className="targetFacts">
          <div><small>Type</small><b>{result.domain ? "Website / Domain" : "Indicator"}</b></div>
          <div><small>Server Address</small><b>{String(result.ip ?? "Not resolved")}</b></div>
          <div><small>Checked at</small><b>{scannedAt}</b></div>
          <div><small>Danger score</small><b>{score(result)} <em>/ 100</em></b></div>
        </div>
      </section>

      <section className="providerPanel">
        <div className="sectionTitle">
          <div>
            <div className="eyebrow">SECURITY DATABASE RESULTS</div>
            <h2>What security services said</h2>
            <p>Independent checks from well-known security databases around the world.</p>
          </div>
          <span className="sourceCount">{entries.length} {entries.length === 1 ? "database" : "databases"} checked</span>
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
                    <b>{meta.flagged ? "⚠️ Threat detected" : meta.configured ? "✅ Nothing found" : "Not connected"}</b>
                    <p>{meta.metric}</p>
                  </div>
                  <span className={`providerState ${meta.flagged ? "flagged" : meta.configured ? "clear" : "off"}`}>
                    {meta.flagged ? "Review" : meta.configured ? "Clean" : "Offline"}
                  </span>
                </article>
              );
            })}
          </div>
        ) : (
          <div style={{ marginTop: 18, color: "var(--muted)", fontSize: 13 }}>
            No external security databases returned data for this item. The score is based on our own internal pattern detection.
          </div>
        )}
      </section>

      <details className="raw">
        <summary>
          <span>🔧 Raw Technical Data (for IT teams)</span>
          <small>JSON format</small>
        </summary>
        <pre>{JSON.stringify(result, null, 2)}</pre>
      </details>
    </div>
  );
}

function providerMeta(name: string, feed: any) {
  const label =
    name === "otx" ? "AlienVault OTX"
    : name === "virustotal" ? "VirusTotal"
    : name === "abuseipdb" ? "AbuseIPDB"
    : name;
  const configured = feed?.enabled !== false;
  const flagged =
    Boolean(feed?.listed) ||
    Number(feed?.malicious ?? feed?.malicious_votes ?? 0) > 0 ||
    Number(feed?.abuseConfidence ?? feed?.abuse_confidence ?? 0) >= 25;
  const metric =
    name === "virustotal"
      ? `${feed?.malicious ?? feed?.malicious_votes ?? 0} security engines flagged this`
      : name === "otx"
      ? `${feed?.pulseCount ?? feed?.pulse_count ?? 0} threat reports found`
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
    onDropRejected: () => toast.error("Please choose a valid file."),
  });

  return (
    <div {...drop.getRootProps({ className: `dropzone ${drop.isDragActive ? "over" : ""}` })}>
      <input {...drop.getInputProps()} />
      <span>↥</span>
      <h2>
        {busy
          ? "Examining the file — please wait…"
          : drop.isDragActive
          ? "Drop it here to check"
          : "Drag a file here, or click to choose one"}
      </h2>
      <p style={{ color: "var(--muted)", fontSize: 13, margin: "8px 0 0" }}>
        Works with .exe, .dll, .bat, .ps1, .doc, .zip and most file types.
        <br />We examine it for hidden dangers <b>without running it</b> — completely safe.
      </p>
      <button type="button" className="primaryBtn" style={{ marginTop: 14 }}>Choose File</button>
    </div>
  );
}
