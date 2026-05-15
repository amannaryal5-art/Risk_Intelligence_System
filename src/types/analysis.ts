export type InputType =
  | "ip"
  | "domain"
  | "url"
  | "hash_md5"
  | "hash_sha1"
  | "hash_sha256"
  | "email"
  | "text"
  | "batch";

export interface AnalysisSignal {
  name: string;
  score: number;
  detail: string;
}

export interface ThreatIntelFeed {
  source: string;
  enabled?: boolean;
  listed?: boolean;
  pulse_count?: number;
  abuse_confidence?: number;
  malicious_votes?: number;
  suspicious_votes?: number;
  total_reports?: number;
  country?: string;
  isp?: string;
  vulns?: string[];
  scan_count?: number;
  malicious_count?: number;
}

export interface ThreatIntelIOCResult {
  ioc_type: string;
  value: string;
  reputation_score: number;
  reputation: string;
  listed_in: number;
  first_seen: string;
  feeds: ThreatIntelFeed[];
  flags: string[];
}

export interface ThreatIntelResponse {
  generated_at: string;
  live_feeds: boolean;
  ioc_count: number;
  overall_risk: string;
  max_ioc_score: number;
  ioc_type_breakdown: Record<string, number>;
  results: ThreatIntelIOCResult[];
}

export interface TextAnalysisResponse {
  score: number;
  risk_level: string;
  confidence: number;
  plain_verdict: string;
  top_flags: string[];
  signals: AnalysisSignal[];
  summary: string;
  recommendations: string[];
  dimensions: Record<string, number>;
  link_analysis?: {
    total_links: number;
    high_risk_links: number;
    medium_risk_links: number;
    aggregate_score: number;
    links: Array<Record<string, unknown>>;
  };
  entities?: Record<string, unknown>;
  ioc_intelligence?: ThreatIntelResponse;
  threat_fingerprint?: string | null;
}

export interface WebsiteIntelResponse {
  type: string;
  input: string;
  domain: string;
  ip: string;
  riskScore: number;
  verdict: string;
  summary: string;
  feeds: {
    otx?: {
      pulseCount?: number;
      threatScore?: number;
      raw?: Record<string, unknown>;
    };
    abuseipdb?: {
      abuseConfidence?: number;
      totalReports?: number;
      country?: string;
      isp?: string;
      raw?: Record<string, unknown>;
    };
    virustotal?: {
      malicious?: number;
      suspicious?: number;
      total?: number;
      raw?: Record<string, unknown>;
    };
  };
  scannedAt: string;
}

export interface WebsiteTraceResponse {
  [key: string]: unknown;
}

export interface FileAnalysisResponse {
  filename: string;
  size_bytes: number;
  sha256: string;
  risk_score: number;
  risk_level: string;
  suspicious_signals: string[];
  ioc_intelligence: ThreatIntelResponse;
}

export interface TerminalEntry {
  id: string;
  tone: "info" | "success" | "warning" | "danger";
  message: string;
  timestamp: string;
}

export interface UnifiedAnalysisResult {
  type: InputType;
  input: string;
  score: number;
  verdict: "SAFE" | "CAUTION" | "DANGER" | "CRITICAL";
  summary: string;
  signals: AnalysisSignal[];
  recommendations: string[];
  textAnalysis?: TextAnalysisResponse | null;
  threatIntel?: ThreatIntelResponse | null;
  websiteIntel?: WebsiteIntelResponse | null;
  traceResult?: WebsiteTraceResponse | null;
  fileAnalysis?: FileAnalysisResponse | null;
  extractedIOCs: {
    urls: string[];
    ips: string[];
    domains: string[];
    hashes: string[];
  };
  raw: Record<string, unknown>;
  timings: Record<string, number | null>;
  autoCaseCreated?: boolean;
}
