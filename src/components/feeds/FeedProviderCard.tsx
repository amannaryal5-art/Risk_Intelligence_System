"use client";

import { motion, useReducedMotion } from "framer-motion";

import { QuotaBar } from "@/components/feeds/QuotaBar";
import { TerminalLog } from "@/components/feeds/TerminalLog";
import { cn } from "@/lib/utils";
import type { FeedProvider } from "@/types/feeds";

function latencyClass(latencyMs: number) {
  if (latencyMs <= 0) return "text-muted border-white/10 bg-white/[0.03]";
  if (latencyMs < 500) return "text-success border-success/25 bg-success/10";
  if (latencyMs <= 1500) return "text-warning border-warning/25 bg-warning/10";
  return "text-danger border-danger/25 bg-danger/10";
}

function statusTone(status: FeedProvider["status"]) {
  if (status === "READY") return "border-success/25 bg-success/10 text-success";
  if (status === "DEGRADED") return "border-warning/25 bg-warning/10 text-warning";
  return "border-danger/25 bg-danger/10 text-danger";
}

function verdictTone(verdict: FeedProvider["latestScan"]["verdict"]) {
  if (verdict === "MALICIOUS") return "text-danger";
  if (verdict === "SUSPICIOUS") return "text-warning";
  return "text-success";
}

export function FeedProviderCard({
  provider,
  index,
  isProbing,
}: {
  provider: FeedProvider;
  index: number;
  isProbing: boolean;
}) {
  const reducedMotion = useReducedMotion();
  const statusReady = provider.status === "READY";
  const offline = provider.status === "OFFLINE";
  const terminalLines = [
    `> Snapshot ${provider.latestScan.url}`,
    ...provider.latestScan.fields.map((field) => `> ${field.label}: ${field.value}`),
    `> Threat score: ${provider.latestScan.threatScore}`,
  ];

  return (
    <motion.article
      initial={reducedMotion ? false : { y: 30, opacity: 0 }}
      animate={reducedMotion ? undefined : { y: 0, opacity: 1 }}
      transition={{ delay: index * 0.1, duration: 0.45, ease: "easeOut" }}
      whileHover={reducedMotion ? undefined : { scale: 1.01 }}
      className={cn(
        "group relative overflow-hidden rounded-2xl border border-accent/15 bg-[linear-gradient(180deg,rgba(10,21,32,0.96),rgba(8,16,25,0.96))] p-5 shadow-[0_0_0_1px_rgba(255,255,255,0.02)] transition-shadow hover:shadow-cyan-glow",
        offline && "border-danger/30 opacity-60",
      )}
    >
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,212,255,0.08),transparent_34%)] opacity-80" />
      {isProbing && !reducedMotion ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: [0, 1, 0] }}
          transition={{ duration: 2 }}
          className="pointer-events-none absolute inset-0"
        >
          <div className="absolute inset-0 animate-shimmer bg-[linear-gradient(120deg,transparent,rgba(0,212,255,0.12),transparent)]" />
        </motion.div>
      ) : null}

      <div className="relative space-y-5">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-accent/20 bg-accent/10 font-data text-xl text-accent">
                {provider.icon}
              </div>
              <div>
                <div className="font-heading text-2xl font-semibold uppercase tracking-[0.08em] text-white">
                  {provider.name}
                </div>
                <div className="font-data text-xs uppercase tracking-[0.2em] text-muted">
                  Feed terminal panel
                </div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <div className={cn("inline-flex items-center gap-2 rounded-full border px-3 py-1 font-data text-[11px] uppercase tracking-[0.18em]", statusTone(provider.status))}>
                <span className="relative flex h-2.5 w-2.5 items-center justify-center">
                  <span className={cn("h-2 w-2 rounded-full", provider.status === "READY" ? "bg-success" : provider.status === "DEGRADED" ? "bg-warning" : "bg-danger")} />
                  {statusReady && !reducedMotion ? (
                    <motion.span
                      className="absolute inset-0 rounded-full border border-success/60"
                      animate={{ scale: [1, 1.8], opacity: [1, 0] }}
                      transition={{ duration: 2, repeat: Infinity }}
                    />
                  ) : null}
                </span>
                {provider.status === "DEGRADED" ? "AUTH FAIL" : provider.status}
              </div>
              <span className="rounded-full border border-success/25 bg-success/10 px-3 py-1 font-data text-[11px] uppercase tracking-[0.18em] text-success">
                HTTP {provider.httpCode}
              </span>
              <motion.span
                initial={reducedMotion ? false : { scale: 0.7, opacity: 0 }}
                animate={reducedMotion ? undefined : { scale: 1, opacity: 1 }}
                transition={{ delay: 0.2 + index * 0.08, type: "spring", stiffness: 240, damping: 18 }}
                className={cn(
                  "rounded-full border px-3 py-1 font-data text-[11px] uppercase tracking-[0.18em]",
                  latencyClass(provider.latencyMs),
                )}
              >
                {provider.latencyMs}ms
              </motion.span>
            </div>
          </div>
        </div>

        <div className="min-h-16 border-y border-white/8 py-4 font-data text-sm leading-6 text-slate-300">
          {provider.description}
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between font-data text-[11px] uppercase tracking-[0.22em] text-muted">
            <span>Latest Scan</span>
            <span className="text-accent">{provider.latestScan.url ? "Live" : "Probe Snapshot"}</span>
          </div>
          {offline ? (
            <div className="rounded-xl border border-danger/25 bg-danger/5 p-4">
              <div className="flex items-center gap-2 text-danger">
                <span>X</span>
                <span className="font-data text-xs">
                  {String(provider.latestScan.fields.find((field) => field.label === "Error")?.value || "Connection refused")}
                </span>
              </div>
            </div>
          ) : (
            <TerminalLog lines={terminalLines} verdict={provider.latestScan.verdict} />
          )}
        </div>

        <div className="space-y-3">
          <div className="font-data text-[11px] uppercase tracking-[0.22em] text-muted">
            Capabilities
          </div>
          <div className="flex flex-wrap gap-2">
            {provider.capabilities.map((capability) => (
              <span
                key={capability}
                className="rounded-full border border-accent/15 bg-accent/5 px-3 py-1 font-data text-[11px] uppercase tracking-[0.14em] text-accent/80"
              >
                {capability}
              </span>
            ))}
          </div>
        </div>

        <div className="space-y-3 border-t border-white/8 pt-4">
          <QuotaBar percent={provider.quotaPercent} />
          <div className="flex items-center justify-between font-data text-[11px] uppercase tracking-[0.18em] text-muted">
            <span>{provider.tier}</span>
            <span className={verdictTone(provider.latestScan.verdict)}>Resets in 14h 22m</span>
          </div>
        </div>
      </div>
    </motion.article>
  );
}
