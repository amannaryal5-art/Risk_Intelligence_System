import { api } from "@/lib/api";
import { detectInputType } from "@/lib/detectInputType";
import type {
  InputType,
  TerminalEntry,
  ThreatIntelIOCResult,
  ThreatIntelResponse,
  UnifiedAnalysisResult,
} from "@/types/analysis";

function toVerdict(score: number): UnifiedAnalysisResult["verdict"] {
  if (score >= 84) return "CRITICAL";
  if (score >= 66) return "DANGER";
  if (score >= 35) return "CAUTION";
  return "SAFE";
}

function makeLog(message: string, tone: TerminalEntry["tone"] = "info"): TerminalEntry {
  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    tone,
    message,
    timestamp: new Date().toISOString(),
  };
}

function timingFrom(started: number) {
  return Date.now() - started;
}

function isValidDomain(candidate: string) {
  return /^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/.test(candidate);
}

export const extractIOCs = (text: string) => ({
  urls: text.match(/https?:\/\/[^\s]+/g) ?? [],
  ips: text.match(/\b(\d{1,3}\.){3}\d{1,3}\b/g) ?? [],
  domains:
    text
      .match(/\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b/g)
      ?.filter((value) => isValidDomain(value)) ?? [],
  hashes: [
    ...(text.match(/\b[a-fA-F0-9]{32}\b/g) ?? []),
    ...(text.match(/\b[a-fA-F0-9]{40}\b/g) ?? []),
    ...(text.match(/\b[a-fA-F0-9]{64}\b/g) ?? []),
  ],
});

function threatSummary(intel?: ThreatIntelResponse | null) {
  const top = intel?.results?.[0];
  if (!top) return "";
  return `${top.value} scored ${top.reputation_score}/100 with ${top.listed_in} live feed hits.`;
}

function feedCount(ioc: ThreatIntelIOCResult, source: string, field: keyof ThreatIntelIOCResult["feeds"][number]) {
  return ioc.feeds.find((feed) => feed.source === source)?.[field];
}

export async function fileToBase64(file: File) {
  const buffer = await file.arrayBuffer();
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export async function runAnalysis(
  input: string,
  apiKey: string,
  autopilot: boolean,
  file?: File | null,
  onLog?: (entry: TerminalEntry) => void,
): Promise<UnifiedAnalysisResult> {
  const type = file ? "text" : detectInputType(input);
  const timings: UnifiedAnalysisResult["timings"] = {};
  const raw: Record<string, unknown> = {};
  const extractedIOCs = extractIOCs(input);

  const log = (message: string, tone: TerminalEntry["tone"] = "info") => {
    onLog?.(makeLog(message, tone));
  };

  if (file) {
    log(`-> malware.analyze-file [${file.name}]`);
    const started = Date.now();
    const contentBase64 = await fileToBase64(file);
    const fileAnalysis = await api.analyzeFile(file.name, contentBase64, apiKey);
    timings.fileAnalysis = timingFrom(started);
    raw.fileAnalysis = fileAnalysis;
    const summary = fileAnalysis.suspicious_signals[0] ?? "File analysis completed.";
    return {
      type,
      input: file.name,
      score: fileAnalysis.risk_score,
      verdict: toVerdict(fileAnalysis.risk_score),
      summary,
      signals: fileAnalysis.suspicious_signals.map((signal, index) => ({
        name: `file_signal_${index + 1}`,
        score: 1,
        detail: signal,
      })),
      recommendations: ["Quarantine the file before opening it.", "Review the SHA256 and IOC hits with an analyst."],
      fileAnalysis,
      textAnalysis: null,
      threatIntel: fileAnalysis.ioc_intelligence,
      websiteIntel: null,
      traceResult: null,
      extractedIOCs,
      raw,
      timings,
    };
  }

  if (type === "url") {
    const websiteStarted = Date.now();
    const intelStarted = Date.now();
    const traceStarted = Date.now();
    log("-> website-intel [url]");
    log("-> threat-intel [urls]");
    if (autopilot) log("-> trace-website [autopilot]");
    const [websiteIntel, threatIntel, traceResult] = await Promise.allSettled([
      api.websiteIntel(input, apiKey),
      api.threatIntel({ urls: [input], live_feeds: true }, apiKey),
      autopilot
        ? api.traceWebsite(input, { max_pages: 30, max_depth: 2 }, apiKey)
        : Promise.resolve(null),
    ]);
    timings.websiteIntel = timingFrom(websiteStarted);
    timings.threatIntel = timingFrom(intelStarted);
    timings.traceWebsite = autopilot ? timingFrom(traceStarted) : null;
    raw.websiteIntel = websiteIntel.status === "fulfilled" ? websiteIntel.value : null;
    raw.threatIntel = threatIntel.status === "fulfilled" ? threatIntel.value : null;
    raw.traceResult = traceResult.status === "fulfilled" ? traceResult.value : null;
    const riskScore = Math.max(
      websiteIntel.status === "fulfilled" ? websiteIntel.value.riskScore : 0,
      threatIntel.status === "fulfilled" ? threatIntel.value.max_ioc_score : 0,
    );
    return {
      type,
      input,
      score: riskScore,
      verdict: toVerdict(riskScore),
      summary:
        (websiteIntel.status === "fulfilled" && websiteIntel.value.summary) ||
        (threatIntel.status === "fulfilled" && threatSummary(threatIntel.value)) ||
        "URL analysis completed.",
      signals:
        threatIntel.status === "fulfilled"
          ? threatIntel.value.results.slice(0, 6).map((result) => ({
              name: result.ioc_type,
              score: result.reputation_score / 100,
              detail: `${result.value} (${result.reputation})`,
            }))
          : [],
      recommendations:
        websiteIntel.status === "fulfilled" && websiteIntel.value.verdict !== "SAFE"
          ? ["Avoid browsing further until the IOC hits are reviewed.", "Trace linked infrastructure before sharing the URL."]
          : ["No severe feed signals returned for this URL."],
      textAnalysis: null,
      threatIntel: threatIntel.status === "fulfilled" ? threatIntel.value : null,
      websiteIntel: websiteIntel.status === "fulfilled" ? websiteIntel.value : null,
      traceResult: traceResult.status === "fulfilled" ? traceResult.value : null,
      fileAnalysis: null,
      extractedIOCs,
      raw,
      timings,
    };
  }

  if (type === "ip" || type === "domain" || type.startsWith("hash_") || type === "email") {
    const intelStarted = Date.now();
    const payload =
      type === "ip"
        ? { ips: [input], live_feeds: true }
        : type === "domain"
          ? { domains: [input], live_feeds: true }
          : type === "email"
            ? { domains: [input.split("@")[1]], text: input, live_feeds: true }
            : { hashes: [input], live_feeds: true };
    log(`-> threat-intel [${type}]`);
    const threatIntel = await api.threatIntel(payload, apiKey);
    timings.threatIntel = timingFrom(intelStarted);
    raw.threatIntel = threatIntel;
    const top = threatIntel.results[0];
    const websiteIntel =
      type === "domain" ? await api.websiteIntel(`https://${input}`, apiKey).catch(() => null) : null;
    raw.websiteIntel = websiteIntel;
    const score = Math.max(top?.reputation_score ?? 0, websiteIntel?.riskScore ?? 0);
    return {
      type,
      input,
      score,
      verdict: toVerdict(score),
      summary: websiteIntel?.summary || threatSummary(threatIntel) || "IOC analysis completed.",
      signals:
        threatIntel.results.slice(0, 6).map((result) => ({
          name: result.ioc_type,
          score: result.reputation_score / 100,
          detail: `${result.value} (${result.reputation})`,
        })) ?? [],
      recommendations:
        score >= 66
          ? ["Escalate this IOC for containment or blocking.", "Cross-check related infrastructure and recent sightings."]
          : ["Keep this IOC under monitoring and re-check on recurrence."],
      textAnalysis: null,
      threatIntel,
      websiteIntel,
      traceResult: null,
      fileAnalysis: null,
      extractedIOCs,
      raw,
      timings,
    };
  }

  const textStarted = Date.now();
  const intelStarted = Date.now();
  log("-> analyze [text]");
  log("-> threat-intel [extracted IOCs]");
  const threatPayload = {
    text: input,
    urls: extractedIOCs.urls,
    ips: extractedIOCs.ips,
    domains: extractedIOCs.domains,
    hashes: extractedIOCs.hashes,
    live_feeds: true,
  };
  const [textAnalysis, threatIntel] = await Promise.all([
    api.analyze(input, apiKey),
    api.threatIntel(threatPayload, apiKey),
  ]);
  timings.textAnalysis = timingFrom(textStarted);
  timings.threatIntel = timingFrom(intelStarted);
  raw.textAnalysis = textAnalysis;
  raw.threatIntel = threatIntel;
  const score = Math.max(textAnalysis.score, threatIntel.max_ioc_score);
  const result: UnifiedAnalysisResult = {
    type,
    input,
    score,
    verdict: toVerdict(score),
    summary: textAnalysis.summary || threatSummary(threatIntel) || "Text analysis completed.",
    signals: textAnalysis.signals ?? [],
    recommendations: textAnalysis.recommendations ?? [],
    textAnalysis,
    threatIntel,
    websiteIntel: null,
    traceResult: null,
    fileAnalysis: null,
    extractedIOCs,
    raw,
    timings,
  };

  if (autopilot && score >= 70) {
    log("-> cases.from-analysis [autopilot]", "warning");
    await api.cases.createFromAnalysis(
      {
        title: `Auto-detected ${result.verdict}: ${input.slice(0, 60)}`,
        text: input,
        tags: [type, result.verdict.toLowerCase(), ...(textAnalysis.top_flags ?? []).slice(0, 3)],
      },
      apiKey,
    );
    result.autoCaseCreated = true;
    log("HIGH RISK: Case automatically created", "danger");
  }

  if (threatIntel.results[0]) {
    const top = threatIntel.results[0];
    log(
      `<- IOC top hit ${top.value} | OTX ${feedCount(top, "otx", "pulse_count") ?? 0} | Abuse ${feedCount(top, "abuseipdb", "abuse_confidence") ?? 0} | VT ${feedCount(top, "virustotal", "malicious_votes") ?? 0}`,
      score >= 66 ? "danger" : score >= 35 ? "warning" : "success",
    );
  }

  return result;
}
