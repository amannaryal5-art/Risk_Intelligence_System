export type ScanResult = Record<string, unknown> & { risk_level?: string; score?: number; risk_score?: number; max_ioc_score?: number; overall_risk?: string; input?: string; scanned_at?: string };

const baseUrl = "/api/proxy";

export async function api<T>(path: string, init: RequestInit = {}, key = ""): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, { ...init, headers: { "Content-Type": "application/json", ...(key ? { "X-API-Key": key } : {}), ...init.headers } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const detail = typeof body.detail === "string" ? body.detail : "The request could not be completed.";
    if (response.status === 401) throw new Error("Your API key was rejected. Check it and try again.");
    if (response.status === 429) throw new Error("A threat-intelligence provider is rate-limiting requests. Wait a moment and retry.");
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}
