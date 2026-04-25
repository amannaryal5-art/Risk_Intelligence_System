"use client";

import { motion, useReducedMotion } from "framer-motion";
import { KeyRound, Sparkles, Wrench } from "lucide-react";

import type { SystemHealth } from "@/types/feeds";

function tone(value: number, total: number) {
  if (value >= 4 && total === 5) return "text-success border-success/30 bg-success/10";
  if (value <= 2) return "text-danger border-danger/30 bg-danger/10";
  return "text-warning border-warning/30 bg-warning/10";
}

function barTone(value: number, total: number) {
  if (value >= 4 && total === 5) return "from-success to-accent";
  if (value <= 2) return "from-danger to-warning";
  return "from-warning to-accent";
}

export function SystemHealthBar({ health }: { health: SystemHealth }) {
  const reducedMotion = useReducedMotion();
  const items = [
    { key: "cfg", label: "Configuration", icon: Wrench, value: health.cfg },
    { key: "net", label: "Network Reach", icon: Sparkles, value: health.net },
    { key: "auth", label: "Auth Validity", icon: KeyRound, value: health.auth },
  ] as const;

  return (
    <section className="grid gap-4 rounded-2xl border border-accent/15 bg-surface/80 p-5 lg:grid-cols-3">
      {items.map((item) => {
        const percent = Math.round((item.value.current / item.value.total) * 100);
        const Icon = item.icon;
        return (
          <div
            key={item.key}
            className="rounded-xl border border-white/6 bg-white/[0.02] p-4"
          >
            <div className="mb-3 flex items-center gap-2 font-data text-xs uppercase tracking-[0.22em] text-muted">
              <Icon className="h-4 w-4 text-accent" />
              <span>{item.label}</span>
            </div>
            <div className="mb-2 flex items-end gap-3">
              <span className="font-heading text-3xl font-semibold text-white">
                {item.value.current}
              </span>
              <span className="pb-1 font-data text-sm text-muted">/ {item.value.total} providers</span>
            </div>
            <div
              className={`mb-3 inline-flex rounded-full border px-3 py-1 font-data text-[11px] uppercase tracking-[0.18em] ${tone(item.value.current, item.value.total)}`}
            >
              {percent}% healthy
            </div>
            <div className="h-2 overflow-hidden rounded-full border border-white/8 bg-white/5">
              <motion.div
                className={`h-full rounded-full bg-gradient-to-r ${barTone(item.value.current, item.value.total)}`}
                initial={{ width: 0 }}
                animate={{ width: `${percent}%` }}
                transition={reducedMotion ? { duration: 0 } : { duration: 0.8, ease: "easeOut" }}
              />
            </div>
          </div>
        );
      })}
    </section>
  );
}
