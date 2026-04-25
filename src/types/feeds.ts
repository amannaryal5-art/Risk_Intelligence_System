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

export interface SystemHealth {
  cfg: { current: number; total: number };
  net: { current: number; total: number };
  auth: { current: number; total: number };
}
