"use client";

import { useEffect, useMemo, useState } from "react";
import { useDropzone } from "react-dropzone";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Toaster, toast } from "sonner";
import { api, ScanResult } from "./api";

type View = "scan" | "file" | "history" | "detail";
type Stored = { id: string; at: string; input: string; kind: string; result: ScanResult };
const scanSchema = z.object({ target: z.string().trim().min(3, "Paste a URL, IP, hash, email, or suspicious message.") });

function detect(target: string) {
  const value = target.trim();
  if (/^[a-f\d]{32}$|^[a-f\d]{40}$|^[a-f\d]{64}$/i.test(value)) return "hash";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return "ip";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "email";
  if (/^(https?:\/\/|www\.)/i.test(value)) return "url";
  if (/^[a-z\d-]+(?:\.[a-z\d-]+)+$/i.test(value)) return "domain";
  return "text";
}
function score(result: ScanResult) { return Number(result.risk_score ?? result.score ?? result.max_ioc_score ?? result.confidence ?? 0); }
function risk(result: ScanResult) { const value = String(result.risk_level ?? result.overall_risk ?? result.verdict ?? "unknown").toLowerCase(); if (value === "minimal" || value === "safe") return "low"; if (value === "danger") return "high"; return value; }
function action(level: string) { return level === "critical" || level === "high" ? "Do not open or run it. Block the indicator, preserve evidence, and alert the responsible team." : level === "medium" ? "Treat it with caution. Verify it through a known channel before interacting." : "No strong malicious signal was found. Continue with normal caution."; }

export default function Console() {
  const [view, setView] = useState<View>("scan"); const [result, setResult] = useState<ScanResult | null>(null); const [history, setHistory] = useState<Stored[]>([]); const [busy, setBusy] = useState(false); const [filter, setFilter] = useState("all");
  const form = useForm<z.infer<typeof scanSchema>>({ resolver: zodResolver(scanSchema), defaultValues: { target: "" } });
  useEffect(() => { setHistory(JSON.parse(localStorage.getItem("crie-history") ?? "[]")); }, []);
  function remember(input: string, kind: string, data: ScanResult) { const next = [{ id: crypto.randomUUID(), at: new Date().toISOString(), input, kind, result: data }, ...history].slice(0, 40); setHistory(next); localStorage.setItem("crie-history", JSON.stringify(next)); setResult(data); setView("detail"); }
  async function submit({ target }: z.infer<typeof scanSchema>) { const kind = detect(target); setBusy(true); const id = toast.loading(kind === "text" ? "Analyzing local signals and extracted IOCs…" : "Querying threat-intelligence sources…"); try { let data: ScanResult; if (kind === "url" || kind === "domain") data = await api("/api/v1/website-intel", { method: "POST", body: JSON.stringify({ url: target }) }); else if (kind === "email") data = await api("/api/v1/scamcheck", { method: "POST", body: JSON.stringify({ input: target, detectedType: "email" }) }); else if (kind === "ip" || kind === "hash") data = await api("/api/v1/threat-intel", { method: "POST", body: JSON.stringify(kind === "ip" ? { ips: [target] } : { hashes: [target] }) }); else data = await api("/api/v1/analyze", { method: "POST", body: JSON.stringify({ text: target }) }); toast.success("Scan complete", { id }); remember(target, kind, data); } catch (error) { toast.error(error instanceof Error ? error.message : "Scan failed. Try again.", { id }); } finally { setBusy(false); } }
  async function fileScan(file: File) { setBusy(true); const id = toast.loading("Hashing file and checking threat intelligence…"); try { const content = await file.arrayBuffer(); const data = await api<ScanResult>("/api/v1/malware/analyze-file", { method: "POST", body: JSON.stringify({ filename: file.name, content_base64: btoa(String.fromCharCode(...new Uint8Array(content))) }) }); toast.success("File scan complete", { id }); remember(file.name, "file", data); } catch (error) { toast.error(error instanceof Error ? error.message : "File scan failed.", { id }); } finally { setBusy(false); } }
  const currentKind = detect(form.watch("target") || ""); const visible = useMemo(() => history.filter(item => filter === "all" || risk(item.result) === filter), [history, filter]);
  return <main><Toaster theme="dark" richColors position="top-right" /><header><div className="brand"><span className="mark">◈</span><div><b>CRIE</b><small>Risk intelligence console</small></div></div><nav>{(["scan", "file", "history"] as View[]).map(item => <button key={item} className={view === item ? "active" : ""} onClick={() => setView(item)}>{item === "file" ? "File scan" : item}</button>)}</nav><div className="connection"><i />Backend connected</div></header>
    {view === "scan" && <section className="workspace"><div className="eyebrow">INTELLIGENCE WORKBENCH</div><h1>Know before you click.</h1><p className="lede">Investigate a suspicious URL, IP, hash, email, or message with local scoring and live threat intelligence.</p><form className="command" onSubmit={form.handleSubmit(submit)}><textarea aria-label="Scan target" placeholder="Paste a URL, IP, hash, email, or suspicious message…" {...form.register("target")} /><button disabled={busy}>{busy ? "Scanning…" : "Run scan"}</button></form>{form.formState.errors.target && <p className="error">{form.formState.errors.target.message}</p>}<p className="hint">Detected: <b>{currentKind}</b> · {currentKind === "text" ? "local analysis + IOC enrichment" : "reputation lookup"}</p>{result ? <Result result={result} onDetail={() => setView("detail")} /> : <Empty />}</section>}
    {view === "file" && <FilePanel onFile={fileScan} busy={busy} />}
    {view === "history" && <section className="workspace"><div className="eyebrow">LOCAL HISTORY</div><h1>Previous investigations</h1><div className="filters">{["all", "low", "medium", "high", "critical"].map(item => <button key={item} className={filter === item ? "active" : ""} onClick={() => setFilter(item)}>{item}</button>)}</div>{visible.length ? <div className="history">{visible.map(item => <button className="historyRow" key={item.id} onClick={() => { setResult(item.result); setView("detail"); }}><RiskDot level={risk(item.result)} /><span><b>{item.input}</b><small>{item.kind} · {new Date(item.at).toLocaleString()}</small></span><strong>{score(item.result)}/100</strong></button>)}</div> : <Empty text="Your completed scans stay in this browser. Run your first check to build a useful trail." />}</section>}
    {view === "detail" && result && <section className="workspace detail"><button className="back" onClick={() => setView("scan")}>Back to scan</button><Result result={result} /><IntelDetail result={result} /></section>}</main>;
}

function Result({ result, onDetail }: { result: ScanResult; onDetail?: () => void }) { const value = score(result), level = risk(result); const sources = (result.ioc_intelligence as Record<string, unknown>)?.results as unknown[] | undefined; return <section className="result"><div className={`horizon ${level}`} style={{ "--score": `${value}%` } as React.CSSProperties}><div className="arc"><b>{value}</b><span>/100</span></div><strong>{level}</strong><small>risk verdict</small></div><div className="summary"><div className="eyebrow">ASSESSMENT</div><h2>{level === "critical" || level === "high" ? "Dangerous signals detected" : level === "medium" ? "Suspicious indicators found" : "No strong malicious signal"}</h2><p>{action(level)}</p><div className="chips"><span>{result.input ? "target analyzed" : "scan complete"}</span><span>{sources?.length ?? 0} IOC results</span></div>{onDetail && <button onClick={onDetail}>Open result detail →</button>}</div><div className="evidence"><h3>Why this score</h3>{Array.isArray(result.signals) && result.signals.length ? result.signals.slice(0, 4).map((signal: any, index) => <p key={index}><RiskDot level={level} />{signal.detail ?? signal.name}</p>) : <p><RiskDot level={level} />Provider and heuristic evidence is available in the detail view.</p>}</div></section> }
function RiskDot({ level }: { level: string }) { return <i className={`dot ${level}`} /> }
function providerMeta(name: string, feed: any) {
  const label = name === "otx" ? "AlienVault OTX" : name === "virustotal" ? "VirusTotal" : name === "abuseipdb" ? "AbuseIPDB" : name;
  const configured = feed?.enabled !== false;
  const flagged = Boolean(feed?.listed) || Number(feed?.malicious ?? feed?.malicious_votes ?? 0) > 0 || Number(feed?.abuseConfidence ?? feed?.abuse_confidence ?? 0) >= 25;
  const metric = name === "virustotal" ? `${feed?.malicious ?? feed?.malicious_votes ?? 0} malicious detections` : name === "otx" ? `${feed?.pulseCount ?? feed?.pulse_count ?? 0} threat pulses` : `${feed?.abuseConfidence ?? feed?.abuse_confidence ?? 0}% abuse confidence`;
  return { label, configured, flagged, metric };
}
function IntelDetail({ result }: { result: ScanResult }) {
  const feeds = (result.feeds ?? {}) as Record<string, any>;
  const entries = Object.entries(feeds);
  const level = risk(result);
  const target = String(result.domain ?? result.input ?? "Scanned target");
  const scannedAt = result.scanned_at ? new Date(String(result.scanned_at)).toLocaleString() : "Just now";
  return <div className="intelDetail">
    <section className="targetCard">
      <div className="targetTop"><div><div className="eyebrow">TARGET PROFILE</div><h2 title={target}>{target}</h2></div><span className={`verdictBadge ${level}`}>{level} risk</span></div>
      <div className="targetFacts"><div><small>Target type</small><b>{result.domain ? "Domain / URL" : "Indicator"}</b></div><div><small>Resolved address</small><b>{String(result.ip ?? "Not resolved")}</b></div><div><small>Scan time</small><b>{scannedAt}</b></div><div><small>Confidence score</small><b>{score(result)} <em>/ 100</em></b></div></div>
    </section>
    <section className="providerPanel">
      <div className="sectionTitle"><div><div className="eyebrow">SOURCE VERIFICATION</div><h2>Reputation checks</h2><p>Independent provider results for this indicator.</p></div><span className="sourceCount">{entries.length} {entries.length === 1 ? "source" : "sources"}</span></div>
      {entries.length ? <div className="providers">{entries.map(([name, feed]) => { const meta = providerMeta(name, feed); return <article key={name} className={meta.flagged ? "flagged" : ""}><div className="providerIcon">{meta.label.slice(0, 1)}</div><div className="providerInfo"><small>{meta.label}</small><b>{meta.flagged ? "Signal detected" : meta.configured ? "No detection" : "Not configured"}</b><p>{meta.metric}</p></div><span className={`providerState ${meta.flagged ? "flagged" : meta.configured ? "clear" : "off"}`}>{meta.flagged ? "Review" : meta.configured ? "Clear" : "Offline"}</span></article>; })}</div> : <div className="noProviders">No external sources returned data for this scan. The score reflects the local analysis only.</div>}
    </section>
    <section className={`actionPanel ${level}`}><div className="actionIcon">!</div><div><div className="eyebrow">ANALYST RECOMMENDATION</div><h2>{level === "low" ? "Proceed with awareness" : "Take a closer look"}</h2><p>{action(level)}</p></div><button onClick={() => navigator.clipboard.writeText(JSON.stringify(result, null, 2)).then(() => toast.success("Technical report copied"))}>Copy report</button></section>
    <details className="raw"><summary><span>Technical data</span><small>Raw JSON for investigation</small></summary><pre>{JSON.stringify(result, null, 2)}</pre></details>
  </div>;
}
function Empty({ text = "Paste a URL, IP, file hash, email, or suspicious message above to get started." }: { text?: string }) { return <div className="empty"><span>⌁</span><p>{text}</p></div> }
function FilePanel({ onFile, busy }: { onFile: (file: File) => void; busy: boolean }) { const drop = useDropzone({ multiple: false, disabled: busy, onDropAccepted: files => onFile(files[0]), onDropRejected: () => toast.error("Choose one file under your browser’s upload limit.") }); return <section className="workspace"><div className="eyebrow">FILE INTELLIGENCE</div><h1>Check a file before it runs.</h1><p className="lede">The file stays in your browser until you choose to submit it for hash and content analysis.</p><div {...drop.getRootProps({ className: `dropzone ${drop.isDragActive ? "over" : ""}` })}><input {...drop.getInputProps()} /><span>↥</span><h2>{busy ? "Checking file intelligence…" : drop.isDragActive ? "Drop to scan" : "Drop a file here"}</h2><p>or choose a file · executable and script signals are checked</p><button type="button">Choose file</button></div></section> }
