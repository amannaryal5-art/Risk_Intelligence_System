export interface FeedProbeResult {
  name: string;
  display_name: string;
  configured: boolean;
  reachable: boolean;
  auth_valid: boolean;
  latency_ms: number | null;
  http_status: number | null;
  error: string | null;
  last_checked: string;
}

export interface FeedSummary {
  configured: number;
  reachable: number;
  auth_valid: number;
  total: number;
}

export interface FeedStatusResponse {
  timestamp: string;
  feeds: FeedProbeResult[];
  summary: FeedSummary;
}

export interface SystemHealth {
  cfg: { current: number; total: number };
  net: { current: number; total: number };
  auth: { current: number; total: number };
}

export interface FeedProvider {
  id: string;
  name: string;
  description: string;
  status: "READY" | "ERROR" | "DEGRADED" | "OFFLINE";
  httpCode: number;
  latencyMs: number;
  quotaPercent: number;
  tier: string;
  capabilities: string[];
  latestScan: {
    url: string;
    fields: { label: string; value: string | number }[];
    threatScore: string;
    verdict: "CLEAN" | "SUSPICIOUS" | "MALICIOUS";
  };
  icon: string;
}
