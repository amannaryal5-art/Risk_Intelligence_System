import type {
  FileAnalysisResponse,
  TextAnalysisResponse,
  ThreatIntelResponse,
  WebsiteIntelResponse,
  WebsiteTraceResponse,
} from "@/types/analysis";
import type { CaseListResponse, RiskCase } from "@/types/cases";
import type { FeedStatusResponse } from "@/types/feeds";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "https://risk-intelligence-system.vercel.app";

export interface ThreatIntelPayload {
  text?: string;
  urls?: string[];
  domains?: string[];
  ips?: string[];
  hashes?: string[];
  live_feeds?: boolean;
}

export interface FusionPayload {
  text?: string;
  website_url?: string;
  max_pages?: number;
  max_depth?: number;
  include_external?: boolean;
  exhaustive?: boolean;
}

function browserApiKey() {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem("riskintel_api_key")?.trim() ?? "";
}

export function apiHeaders(apiKey?: string, extra?: HeadersInit): HeadersInit {
  const resolvedKey = apiKey ?? browserApiKey();
  return {
    "Content-Type": "application/json",
    ...(resolvedKey ? { "X-API-Key": resolvedKey } : {}),
    ...extra,
  };
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body?.detail) detail = body.detail;
    } catch {}
    throw new Error(detail || `Request failed with ${response.status}`);
  }
  return (await response.json()) as T;
}

async function authenticatedGet<T>(path: string, apiKey?: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "GET",
    headers: apiHeaders(apiKey),
  });
  return parseResponse<T>(response);
}

async function authenticatedPost<T>(path: string, body: unknown, apiKey?: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: apiHeaders(apiKey),
    body: JSON.stringify(body),
  });
  return parseResponse<T>(response);
}

async function authenticatedPatch<T>(path: string, body: unknown, apiKey?: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "PATCH",
    headers: apiHeaders(apiKey),
    body: JSON.stringify(body),
  });
  return parseResponse<T>(response);
}

async function authenticatedDelete(path: string, apiKey?: string): Promise<void> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "DELETE",
    headers: apiHeaders(apiKey),
  });
  if (!response.ok && response.status !== 204) {
    throw new Error(`Delete failed with ${response.status}`);
  }
}

export const api = {
  health: () => fetch(`${API_BASE}/api/v1/health`),
  whoami: (apiKey?: string) =>
    authenticatedGet<{ authenticated: boolean; username: string; role: string; api_key_hash: string }>(
      "/api/v1/auth/whoami",
      apiKey,
    ),
  analyze: (text: string, apiKey?: string) =>
    authenticatedPost<TextAnalysisResponse>("/api/v1/analyze", { text }, apiKey),
  analyzeBatch: (texts: string[], apiKey?: string) =>
    authenticatedPost<{ count: number; results: TextAnalysisResponse[] }>(
      "/api/v1/analyze/batch",
      { texts },
      apiKey,
    ),
  threatIntel: (payload: ThreatIntelPayload, apiKey?: string) =>
    authenticatedPost<ThreatIntelResponse>("/api/v1/threat-intel", payload, apiKey),
  websiteIntel: (url: string, apiKey?: string) =>
    authenticatedPost<WebsiteIntelResponse>("/api/v1/website-intel", { url }, apiKey),
  traceWebsite: (
    url: string,
    opts: { max_pages?: number; max_depth?: number; include_external?: boolean; exhaustive?: boolean } = {},
    apiKey?: string,
  ) => authenticatedPost<WebsiteTraceResponse>("/api/v1/trace-website", { url, ...opts }, apiKey),
  fusionScan: (payload: FusionPayload, apiKey?: string) =>
    authenticatedPost<Record<string, unknown>>("/api/v1/fusion-scan", payload, apiKey),
  analyzeFile: (filename: string, content_base64: string, apiKey?: string) =>
    authenticatedPost<FileAnalysisResponse>(
      "/api/v1/malware/analyze-file",
      { filename, content_base64 },
      apiKey,
    ),
  feedsProbe: (apiKey?: string) => authenticatedGet<FeedStatusResponse>("/api/v1/feeds/probe", apiKey),
  feedsStatus: (apiKey?: string) =>
    authenticatedGet<FeedStatusResponse>("/api/v1/feeds/status/live", apiKey),
  cacheStats: (apiKey?: string) => authenticatedGet<Record<string, unknown>>("/api/v1/cache/stats", apiKey),
  audit: (apiKey?: string) => authenticatedGet<{ count: number; results: Record<string, unknown>[] }>("/api/v1/audit", apiKey),
  cases: {
    list: (
      query: { status?: string; severity?: string; assigned_to?: string; limit?: number; search?: string } = {},
      apiKey?: string,
    ) => {
      const searchParams = new URLSearchParams();
      Object.entries(query).forEach(([key, value]) => {
        if (value !== undefined && value !== "") searchParams.set(key, String(value));
      });
      const suffix = searchParams.toString() ? `?${searchParams.toString()}` : "";
      return authenticatedGet<CaseListResponse>(`/api/v1/cases${suffix}`, apiKey);
    },
    get: (id: number, apiKey?: string) => authenticatedGet<RiskCase>(`/api/v1/cases/${id}`, apiKey),
    create: (payload: Record<string, unknown>, apiKey?: string) =>
      authenticatedPost<RiskCase>("/api/v1/cases", payload, apiKey),
    createFromAnalysis: (payload: { title: string; text: string; tags?: string[]; assigned_to?: string }, apiKey?: string) =>
      authenticatedPost<RiskCase>("/api/v1/cases/from-analysis", payload, apiKey),
    update: (id: number, payload: Record<string, unknown>, apiKey?: string) =>
      authenticatedPatch<RiskCase>(`/api/v1/cases/${id}`, payload, apiKey),
    delete: (id: number, apiKey?: string) => authenticatedDelete(`/api/v1/cases/${id}`, apiKey),
    addComment: (id: number, message: string, apiKey?: string) =>
      authenticatedPost(`/api/v1/cases/${id}/comments`, { message }, apiKey),
  },
};
