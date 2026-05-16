export type RiskLevel = "Critical" | "High" | "Medium" | "Low" | "Clean" | "Unknown";
export type AssetType = "domain" | "ip" | "url" | "email";
export type WebSocketStatus = "connected" | "disconnected" | "reconnecting";

export interface Asset {
  id: number;
  name: string;
  type: AssetType;
  value: string;
  active?: number;
  last_risk_level?: RiskLevel | null;
  last_risk_score?: number | null;
  last_summary?: string | null;
  last_scanned_at?: string | null;
}

export interface AssetStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  clean: number;
  unknown: number;
  unseen_alerts: number;
}

export interface AssetHistoryEntry {
  id: number;
  asset_id: number;
  risk_level?: RiskLevel | null;
  risk_score?: number | null;
  summary?: string | null;
  key_findings?: string;
  recommendations?: string;
  threat_indicators?: string;
  scanned_at?: string | null;
}

export interface AssetSummaryResponse {
  summary: string;
}

export interface AssetAlert {
  id: number;
  asset_id?: number | null;
  asset_value?: string | null;
  risk_level: RiskLevel;
  title: string;
  message: string;
  seen: boolean;
  created_at: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
}

export interface DashboardMetric {
  title: string;
  value: string;
  subtext: string;
  footer: string;
  tone?: "blue" | "green" | "red" | "yellow" | "purple";
  trend?: string;
}

export interface FeedProviderStatus {
  name: string;
  configured?: boolean;
  reachable?: boolean | null;
  auth_valid?: boolean | null;
  latency_ms?: number | null;
  status_code?: number | null;
  error?: string | null;
  last_checked?: string | null;
}

export interface FeedStatusSummary {
  feeds: FeedProviderStatus[];
}
