"use client";

import { motion, useReducedMotion } from "framer-motion";

import { CountUp } from "@/components/shared/CountUp";

export function RiskGauge({ score }: { score: number }) {
  const reducedMotion = useReducedMotion();
  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const sweep = circumference * (220 / 360);
  const fillAmount = (Math.max(0, Math.min(score, 100)) / 100) * sweep;
  const gaugeColor =
    score >= 70 ? "var(--color-danger)" : score >= 30 ? "var(--color-warning)" : "var(--color-success)";

  return (
    <div className="relative flex items-center justify-center">
      <svg viewBox="0 0 200 200" className="h-48 w-48 -rotate-[110deg]">
        <circle
          cx="100"
          cy="100"
          r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth="10"
          strokeDasharray={`${sweep} ${circumference}`}
          strokeLinecap="round"
        />
        <motion.circle
          cx="100"
          cy="100"
          r={radius}
          fill="none"
          stroke={gaugeColor}
          strokeWidth="10"
          strokeDasharray={`${fillAmount} ${circumference}`}
          strokeLinecap="round"
          filter="url(#glow)"
          initial={reducedMotion ? false : { strokeDasharray: `0 ${circumference}` }}
          animate={reducedMotion ? undefined : { strokeDasharray: `${fillAmount} ${circumference}` }}
          transition={{ duration: 1.2, ease: "easeOut", delay: 0.2 }}
        />
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center pt-2 text-center">
        <motion.div
          className="font-heading text-5xl font-bold"
          style={{ color: gaugeColor }}
          initial={reducedMotion ? false : { opacity: 0, scale: 0.5 }}
          animate={reducedMotion ? undefined : { opacity: 1, scale: 1 }}
          transition={{ delay: 0.4, type: "spring", stiffness: 200 }}
        >
          <CountUp from={0} to={score} duration={1} />
        </motion.div>
        <div className="font-data text-[10px] uppercase tracking-[0.3em] text-muted">
          Risk Score
        </div>
      </div>
    </div>
  );
}
