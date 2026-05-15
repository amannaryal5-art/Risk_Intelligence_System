"use client";

import { motion } from "framer-motion";

export function RiskGauge({ score }: { score: number }) {
  const circumference = 2 * Math.PI * 58;
  const dashOffset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;
  const tone =
    score >= 84 ? "#ef4444" : score >= 66 ? "#f97316" : score >= 35 ? "#f59e0b" : "#22c55e";

  return (
    <div className="relative flex h-40 w-40 items-center justify-center">
      <svg viewBox="0 0 140 140" className="h-40 w-40 -rotate-90">
        <circle cx="70" cy="70" r="58" stroke="rgba(255,255,255,0.08)" strokeWidth="12" fill="none" />
        <motion.circle
          cx="70"
          cy="70"
          r="58"
          stroke={tone}
          strokeWidth="12"
          strokeLinecap="round"
          fill="none"
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: dashOffset }}
          transition={{ duration: 1, ease: "easeOut" }}
          strokeDasharray={circumference}
        />
      </svg>
      <div className="absolute text-center">
        <div className="font-heading text-5xl font-semibold text-white">{score}</div>
        <div className="font-data text-xs uppercase tracking-[0.22em] text-muted">Risk Score</div>
      </div>
    </div>
  );
}
