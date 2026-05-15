const listeners = new Map();

export class ApiError extends Error {
  constructor(message, status = 0, payload = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export function on(eventName, handler) {
  const bucket = listeners.get(eventName) ?? new Set();
  bucket.add(handler);
  listeners.set(eventName, bucket);
  return () => bucket.delete(handler);
}

export function emit(eventName, detail = {}) {
  const bucket = listeners.get(eventName);
  if (bucket) {
    bucket.forEach((handler) => handler(detail));
  }
}

export function $(selector, root = document) {
  return root.querySelector(selector);
}

export function $$(selector, root = document) {
  return [...root.querySelectorAll(selector)];
}

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function sanitizeText(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

export function debounce(fn, wait = 300) {
  let timer = 0;
  return (...args) => {
    clearTimeout(timer);
    timer = window.setTimeout(() => fn(...args), wait);
  };
}

export function throttle(fn, wait = 16) {
  let locked = false;
  let lastArgs = null;
  return (...args) => {
    if (locked) {
      lastArgs = args;
      return;
    }
    fn(...args);
    locked = true;
    window.setTimeout(() => {
      locked = false;
      if (lastArgs) {
        fn(...lastArgs);
        lastArgs = null;
      }
    }, wait);
  };
}

export function relativeTime(value) {
  if (!value) return "--";
  const stamp = typeof value === "number" ? value : Date.parse(value);
  if (Number.isNaN(stamp)) return "--";
  const seconds = Math.round((Date.now() - stamp) / 1000);
  if (seconds < 10) return `${Math.max(0, seconds)}s ago`;
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function formatTimestamp(value) {
  if (!value) return "--";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "--" : date.toLocaleString();
}

export function formatNumber(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "--";
  return Number(value).toLocaleString();
}

export function formatPercent(value, digits = 0) {
  const numeric = Number(value ?? 0);
  return `${numeric.toFixed(digits)}%`;
}

export function severityTone(value) {
  const severity = String(value ?? "").toLowerCase();
  if (severity.includes("critical")) return "critical";
  if (severity.includes("high")) return "high";
  if (severity.includes("medium")) return "medium";
  if (severity.includes("low")) return "low";
  if (severity.includes("clean") || severity.includes("healthy") || severity.includes("resolved")) return "clean";
  return "neutral";
}

export function pick(obj, paths = [], fallback = null) {
  for (const path of paths) {
    const result = path.split(".").reduce((acc, key) => (acc && acc[key] !== undefined ? acc[key] : undefined), obj);
    if (result !== undefined && result !== null) return result;
  }
  return fallback;
}

export async function copyText(value) {
  const text = String(value ?? "");
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  document.body.append(area);
  area.select();
  document.execCommand("copy");
  area.remove();
}

export function buildUrl(path, params = {}) {
  const url = new URL(path, window.location.origin);
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, value);
    }
  });
  return `${url.pathname}${url.search}`;
}

export async function sleep(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function parsePayload(response) {
  const type = (response.headers.get("content-type") || "").toLowerCase();
  if (type.includes("application/json")) return response.json();
  return response.text();
}

export async function request(path, options = {}, config = {}) {
  const { timeout = 12000, retries = 2, retryDelay = 500, allow404 = false } = config;
  let attempt = 0;
  while (attempt <= retries) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(path, {
        credentials: "same-origin",
        ...options,
        headers: {
          Accept: "application/json",
          ...(options.headers || {}),
        },
        signal: controller.signal,
      });
      const payload = await parsePayload(response);
      if (!response.ok) {
        if (allow404 && response.status === 404) return null;
        if (response.status === 401 || response.status === 403) {
          emit("auth:expired", { status: response.status });
        }
        const detail = typeof payload === "string"
          ? payload
          : payload?.detail || payload?.message || `HTTP ${response.status}`;
        throw new ApiError(detail, response.status, payload);
      }
      return payload;
    } catch (error) {
      if (attempt === retries || error instanceof ApiError) {
        if (error?.name === "AbortError") {
          throw new ApiError(`Request timed out for ${path}`);
        }
        throw error;
      }
      await sleep(retryDelay * (attempt + 1));
      attempt += 1;
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}

export function jsonRequest(path, options = {}, config = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  return request(path, { ...options, headers }, config);
}

export function classNames(...values) {
  return values.filter(Boolean).join(" ");
}

export function iconForIoc(type = "") {
  const normalized = String(type).toLowerCase();
  if (normalized.includes("domain")) return "🌐";
  if (normalized === "ip") return "📍";
  if (normalized.includes("url")) return "🔗";
  if (normalized.includes("hash")) return "#️⃣";
  if (normalized.includes("email")) return "📧";
  return "•";
}

export function middleEllipsis(value, head = 12, tail = 8) {
  const text = String(value ?? "");
  if (text.length <= head + tail + 3) return text;
  return `${text.slice(0, head)}...${text.slice(-tail)}`;
}

export function toArray(value) {
  return Array.isArray(value) ? value : [];
}

export function jsonPreview(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "{}";
  }
}
