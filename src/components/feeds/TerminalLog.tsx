"use client";

import { motion, useReducedMotion } from "framer-motion";

const terminalVariants = {
  hidden: {},
  show: {
    transition: {
      staggerChildren: 0.3,
    },
  },
};

const lineVariants = {
  hidden: { opacity: 0, y: 6 },
  show: { opacity: 1, y: 0 },
};

export function TerminalLog({
  lines,
  verdict,
}: {
  lines: string[];
  verdict: "CLEAN" | "SUSPICIOUS" | "MALICIOUS";
}) {
  const reducedMotion = useReducedMotion();
  const verdictTone =
    verdict === "MALICIOUS"
      ? "border-danger/40 bg-danger/10 text-danger shadow-[0_0_18px_rgba(255,51,102,0.18)]"
      : verdict === "SUSPICIOUS"
        ? "border-warning/40 bg-warning/10 text-warning shadow-[0_0_18px_rgba(255,170,0,0.16)]"
        : "border-success/40 bg-success/10 text-success shadow-[0_0_18px_rgba(0,255,136,0.16)]";

  return (
    <div className="relative overflow-hidden rounded-xl border border-accent/15 bg-black/35 p-4">
      <div className="pointer-events-none absolute inset-0 bg-[repeating-linear-gradient(180deg,rgba(255,255,255,0.04)_0,rgba(255,255,255,0.04)_1px,transparent_1px,transparent_4px)] opacity-10" />
      <motion.div
        variants={terminalVariants}
        initial="hidden"
        animate="show"
        className="relative space-y-2 font-data text-xs text-accent/70"
      >
        {lines.map((line) => (
          <motion.div
            key={line}
            variants={reducedMotion ? undefined : lineVariants}
            className="whitespace-pre-wrap"
          >
            {line}
          </motion.div>
        ))}
      </motion.div>
      <div className="relative mt-4 flex items-center justify-between">
        <span
          className={`inline-flex rounded-full border px-3 py-1 font-data text-[11px] uppercase tracking-[0.18em] ${verdictTone}`}
        >
          {verdict}
        </span>
        <span className="font-data text-sm text-accent/70">
          <span className="animate-blink">_</span>
        </span>
      </div>
    </div>
  );
}
