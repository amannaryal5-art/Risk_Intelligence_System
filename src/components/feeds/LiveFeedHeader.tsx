"use client";

import { motion, useReducedMotion } from "framer-motion";

import { ProbeButton } from "@/components/feeds/ProbeButton";
import { PulseDot } from "@/components/shared/PulseDot";
import { cn } from "@/lib/utils";

export function LiveFeedHeader({
  formattedTime,
  isProbing,
  isConnected,
  refreshSpin,
  onProbe,
  onRefresh,
}: {
  formattedTime: string;
  isProbing: boolean;
  isConnected: boolean;
  refreshSpin: number;
  onProbe: () => void;
  onRefresh: () => void;
}) {
  const reducedMotion = useReducedMotion();

  return (
    <header className="space-y-5 rounded-2xl border border-accent/15 bg-panel-grid p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
      <div className="grid gap-4 lg:grid-cols-[1fr_auto_1fr] lg:items-center">
        <div className="font-data text-xs uppercase tracking-[0.28em] text-muted">
          Feeds &gt; Live Feed Status
        </div>
        <div className="flex items-center justify-center gap-3">
          <div className="inline-flex items-center gap-3 rounded-full border border-success/30 bg-success/10 px-4 py-2 font-data text-xs uppercase tracking-[0.26em] text-success shadow-green-glow">
            <PulseDot color="success" />
            <span className="animate-blink">Live</span>
          </div>
          <span
            className={cn(
              "rounded-full border px-3 py-1 font-data text-[10px] uppercase tracking-[0.2em]",
              isConnected
                ? "border-success/30 bg-success/10 text-success"
                : "border-warning/30 bg-warning/10 text-warning",
            )}
          >
            {isConnected ? "WS Connected" : "Polling 30s"}
          </span>
        </div>
        <div className="flex items-center justify-start gap-4 lg:justify-end">
          <div className="font-data text-sm text-slate-200">
            Last checked: <span className="text-accent">{formattedTime}</span>
          </div>
          <ProbeButton
            isProbing={isProbing}
            refreshSpin={refreshSpin}
            onProbe={onProbe}
            onRefresh={onRefresh}
          />
        </div>
      </div>
      <div className="space-y-2">
        <div className="font-heading text-4xl font-semibold uppercase tracking-[0.08em] text-white">
          Live Feed Status
        </div>
        <div className="font-data text-sm text-muted">
          {isConnected ? "Live websocket transport connected" : "Polling fallback active"}
        </div>
        <div className="h-px overflow-hidden rounded-full bg-white/5">
          <motion.div
            className="h-full w-full bg-[linear-gradient(90deg,transparent,rgba(0,212,255,0.8),transparent)] bg-[length:120px_1px]"
            animate={reducedMotion ? undefined : { backgroundPosition: ["0 0", "120px 0"] }}
            transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
          />
        </div>
      </div>
    </header>
  );
}
