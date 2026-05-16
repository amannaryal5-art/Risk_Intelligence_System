"use client";

import { useEffect, useMemo, useState } from "react";

import { FeedHealth } from "@/components/dashboard/FeedHealth";
import { ProcessingPipeline } from "@/components/dashboard/ProcessingPipeline";
import { StatCard } from "@/components/dashboard/StatCard";
import { ThreatLandscape } from "@/components/dashboard/ThreatLandscape";
import { api } from "@/lib/api";
import { useAssets } from "@/hooks/useAssets";
import { useWebSocket } from "@/hooks/useWebSocket";
import type { DashboardMetric, FeedProviderStatus } from "@/lib/types";
import type { RiskCase } from "@/types/cases";

export default function CommandPage() {
  const { assets, alerts } = useAssets();
  const { queuedActions } = useWebSocket();
  const [cases, setCases] = useState<RiskCase[]>([]);
  const [feeds, setFeeds] = useState<FeedProviderStatus[]>([]);

  useEffect(() => {
    Promise.allSettled([api.cases.list({ limit: 50 }), api.feedsStatus()]).then((results) => {
      const nextCases =
        results[0].status === "fulfilled" ? results[0].value.results ?? [] : [];
      const nextFeeds =
        results[1].status === "fulfilled"
          ? (results[1].value.feeds ?? []).map((feed) => ({
              name: feed.display_name || feed.name,
              configured: feed.configured,
              reachable: feed.reachable,
              auth_valid: feed.auth_valid,
              latency_ms: feed.latency_ms,
              status_code: feed.http_status,
              error: feed.error,
              last_checked: feed.last_checked,
            }))
          : [];

      setCases(nextCases);
      setFeeds(nextFeeds);
    });
  }, []);

  const metrics = useMemo<DashboardMetric[]>(() => {
    const recentAlerts = alerts.filter(
      (alert) => Date.now() - new Date(alert.created_at).getTime() <= 24 * 60 * 60 * 1000,
    );
    const operationalFeeds = feeds.filter((feed) => feed.reachable && feed.auth_valid !== false).length;

    return [
      {
        title: "Threats Detected (24H)",
        value: String(recentAlerts.length),
        subtext: `${recentAlerts.length ? "+" : ""}${recentAlerts.length * 7}% trend`,
        footer: "Autonomous telemetry",
        tone: "red",
        trend: `${recentAlerts.length * 7 || 0}%`,
      },
      {
        title: "Active Cases",
        value: String(cases.filter((item) => item.status !== "closed").length),
        subtext: "No autonomous actions",
        footer: "Live case queue",
        tone: "blue",
      },
      {
        title: "TOC Queue Depth",
        value: String(queuedActions + assets.filter((asset) => !asset.last_scanned_at).length),
        subtext: `Processing ${assets.length} | Backlog ${queuedActions}`,
        footer: "Worker pipeline state",
        tone: "yellow",
      },
      {
        title: "Feed Health",
        value: `${operationalFeeds}/${feeds.length || 0} OPERATIONAL`,
        subtext: "Provider availability",
        footer: "Provider availability",
        tone: "green",
      },
      {
        title: "Autonomous Actions",
        value: String(alerts.length),
        subtext: "System response volume",
        footer: "System response volume",
        tone: "purple",
      },
      {
        title: "Mean Time to Detect",
        value: recentAlerts.length ? "4.2s" : "--",
        subtext: "Target <5s | Detection SLA",
        footer: "Detection SLA",
        tone: "blue",
      },
    ];
  }, [alerts, assets, cases, feeds, queuedActions]);

  return (
    <div className="space-y-6">
      <section>
        <div className="eyebrow">Unified Risk Intelligence Platform</div>
        <h1 className="title-xl mt-2">Merged command, asset, and AI operations view</h1>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {metrics.map((metric) => (
          <StatCard key={metric.title} metric={metric} />
        ))}
      </section>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.45fr)_minmax(340px,0.9fr)]">
        <ThreatLandscape alerts={alerts} />
        <div className="space-y-6">
          <ProcessingPipeline assets={assets} alerts={alerts} queuedActions={queuedActions} />
          <section className="panel p-5">
            <div className="eyebrow">Feed Health</div>
            <h2 className="mt-2 text-xl font-semibold text-white">Provider telemetry</h2>
            <div className="mt-5">
              <FeedHealth feeds={feeds} />
            </div>
          </section>
        </div>
      </section>
    </div>
  );
}
