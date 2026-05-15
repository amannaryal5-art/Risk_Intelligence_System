"use client";

import { useMemo, useState } from "react";

import { FeedProviderCard } from "@/components/feeds/FeedProviderCard";
import { FeedStatusFooter } from "@/components/feeds/FeedStatusFooter";
import { LiveFeedHeader } from "@/components/feeds/LiveFeedHeader";
import { SystemHealthBar } from "@/components/feeds/SystemHealthBar";
import { useLiveFeedPolling } from "@/hooks/useLiveFeedPolling";
import type { FeedProbeResult, FeedProvider, SystemHealth } from "@/types/feeds";

const providerMeta: Record<
  string,
  { icon: string; description: string; capabilities: string[]; tier: string }
> = {
  alienvault_otx: {
    icon: "O",
    description:
      "Open threat intelligence community with pulse-driven enrichment for domains, URLs, IPs, and file hashes.",
    capabilities: ["Pulse correlation", "IOC reputation", "Community context", "Tag enrichment"],
    tier: "External feed",
  },
  abuseipdb: {
    icon: "A",
    description:
      "Abuse-driven IP intelligence focused on confidence scoring, reporter history, and infrastructure abuse patterns.",
    capabilities: ["IP abuse scoring", "Reporter counts", "Geo hints", "ISP attribution"],
    tier: "External feed",
  },
  virustotal: {
    icon: "V",
    description:
      "Multi-engine verdict aggregation for files, URLs, domains, and IP addresses across antivirus engines.",
    capabilities: ["Malicious votes", "Suspicious votes", "Engine consensus", "Hash lookup"],
    tier: "External feed",
  },
};

function mapStatus(feed: FeedProbeResult): FeedProvider["status"] {
  if (feed.reachable && feed.auth_valid) return "READY";
  if (feed.reachable) return "DEGRADED";
  return "OFFLINE";
}

function latestVerdict(feed: FeedProbeResult): FeedProvider["latestScan"]["verdict"] {
  if (feed.reachable && feed.auth_valid) return "CLEAN";
  if (feed.reachable) return "SUSPICIOUS";
  return "MALICIOUS";
}

function relativeTime(timestamp: string | null) {
  if (!timestamp) return "Never";
  const diffSeconds = Math.max(0, Math.round((Date.now() - new Date(timestamp).getTime()) / 1000));
  if (diffSeconds < 60) return `${diffSeconds}s ago`;
  const minutes = Math.round(diffSeconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  return `${hours}h ago`;
}

export default function LiveFeedsPage() {
  const apiKey =
    typeof window !== "undefined" ? window.localStorage.getItem("riskintel_api_key")?.trim() ?? "" : "";
  const { feedData, formattedTime, isConnected, isProbing, runProbe, lastUpdated } = useLiveFeedPolling(apiKey);
  const [toast, setToast] = useState<string | null>(null);
  const [refreshSpin, setRefreshSpin] = useState(0);

  const health = useMemo<SystemHealth>(() => {
    const summary = feedData?.summary ?? { configured: 0, reachable: 0, auth_valid: 0, total: 0 };
    return {
      cfg: { current: summary.configured, total: summary.total || 1 },
      net: { current: summary.reachable, total: summary.total || 1 },
      auth: { current: summary.auth_valid, total: summary.total || 1 },
    };
  }, [feedData]);

  const providers = useMemo<FeedProvider[]>(() => {
    return (feedData?.feeds ?? []).map((feed) => {
      const meta = providerMeta[feed.name] ?? {
        icon: "?",
        description: "Live feed probe with real backend connectivity checks.",
        capabilities: ["Reachability", "Auth validation", "Latency"],
        tier: "External feed",
      };
      return {
        id: feed.name,
        name: feed.display_name,
        description: meta.description,
        status: mapStatus(feed),
        httpCode: feed.http_status ?? 0,
        latencyMs: feed.latency_ms ?? 0,
        quotaPercent: feed.auth_valid ? 82 : feed.reachable ? 45 : 12,
        tier: meta.tier,
        capabilities: meta.capabilities,
        icon: meta.icon,
        latestScan: {
          url: relativeTime(feed.last_checked),
          fields: [
            { label: "Configured", value: feed.configured ? "Yes" : "No" },
            { label: "Reachable", value: feed.reachable ? "Yes" : "No" },
            { label: "Auth Valid", value: feed.auth_valid ? "Yes" : "No" },
            { label: "Error", value: feed.error ?? "None" },
          ],
          threatScore: `${feed.auth_valid ? 0 : feed.reachable ? 45 : 85}/100`,
          verdict: latestVerdict(feed),
        },
      };
    });
  }, [feedData]);

  const handleRefresh = async () => {
    setRefreshSpin((value) => value + 1);
    await runProbe();
    setToast("Feed probe completed");
    window.setTimeout(() => setToast(null), 1800);
  };

  return (
    <main className="min-h-screen bg-bg px-4 pb-8 pt-24 text-white lg:px-8">
      <div className="mx-auto max-w-[1600px] space-y-6">
        <LiveFeedHeader
          formattedTime={`${formattedTime} · ${relativeTime(lastUpdated)}`}
          isConnected={isConnected}
          isProbing={isProbing}
          refreshSpin={refreshSpin}
          onProbe={runProbe}
          onRefresh={handleRefresh}
        />

        <SystemHealthBar health={health} />

        <section className="grid grid-cols-1 gap-5 lg:grid-cols-3">
          {providers.map((provider, index) => (
            <FeedProviderCard
              key={provider.id}
              provider={provider}
              index={index}
              isProbing={isProbing}
            />
          ))}
        </section>

        <FeedStatusFooter isConnected={isConnected} />
      </div>

      {toast ? (
        <div className="fixed bottom-6 right-6 rounded-lg border border-accent/25 bg-panel px-4 py-3 font-data text-xs uppercase tracking-[0.2em] text-accent shadow-cyan-glow">
          {toast}
        </div>
      ) : null}
    </main>
  );
}
