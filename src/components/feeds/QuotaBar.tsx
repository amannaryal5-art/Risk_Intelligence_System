"use client";

import { motion, useReducedMotion } from "framer-motion";

export function QuotaBar({ percent }: { percent: number }) {
  const reducedMotion = useReducedMotion();

  return (
    <div className="space-y-2">
      <div className="h-2 overflow-hidden rounded-full border border-white/10 bg-white/5">
        <motion.div
          className="h-full rounded-full bg-[linear-gradient(90deg,rgba(0,212,255,0.95),rgba(0,255,136,0.72))]"
          initial={{ width: 0 }}
          animate={{ width: `${percent}%` }}
          transition={reducedMotion ? { duration: 0 } : { duration: 0.8, ease: "easeOut" }}
        />
      </div>
      <div className="flex items-center justify-between font-data text-[11px] uppercase tracking-[0.18em] text-muted">
        <span>API quota</span>
        <span>{percent}% remaining</span>
      </div>
    </div>
  );
}
