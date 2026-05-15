"use client";

import { motion, useReducedMotion } from "framer-motion";
import { useState } from "react";

import { IOCTable } from "@/components/results/IOCTable";
import { RiskGauge } from "@/components/results/RiskGauge";
import { SignalsList } from "@/components/results/SignalsList";
import { VerdictBadge } from "@/components/results/VerdictBadge";
import { WebsitePanel } from "@/components/results/WebsitePanel";
import type { UnifiedAnalysisResult } from "@/types/analysis";

const tabs = [
  { id: "signals", label: "Signals" },
  { id: "ioc", label: "IOC Intel" },
  { id: "website", label: "Website" },
  { id: "raw", label: "Raw JSON" },
] as const;

export function ResultsPanel({ result }: { result: UnifiedAnalysisResult }) {
  const [activeTab, setActiveTab] = useState<(typeof tabs)[number]["id"]>("signals");
  const reducedMotion = useReducedMotion();

  return (
    <motion.section
      initial={reducedMotion ? false : { y: 30, opacity: 0 }}
      animate={reducedMotion ? undefined : { y: 0, opacity: 1 }}
      className="rounded-2xl border border-accent/15 bg-gradient-to-b from-surface to-panel p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]"
    >
      <div className="space-y-4">
        <div className="flex flex-col items-center gap-4 text-center">
          <RiskGauge score={result.score} />
          <VerdictBadge verdict={result.verdict} />
          <p className="max-w-md font-data text-sm leading-relaxed text-slate-400">
            {result.summary}
          </p>
        </div>

        <div className="flex rounded-xl border border-white/8 bg-white/[0.02] p-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={
                activeTab === tab.id
                  ? "flex-1 rounded-lg bg-accent/15 px-3 py-2 font-data text-[11px] uppercase tracking-[0.18em] text-accent shadow-[0_0_12px_rgba(0,212,255,0.12)] transition-all duration-200"
                  : "flex-1 rounded-lg px-3 py-2 font-data text-[11px] uppercase tracking-[0.18em] text-muted transition-all duration-200 hover:text-white"
              }
            >
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === "signals" ? <SignalsList signals={result.signals} /> : null}
        {activeTab === "ioc" ? <IOCTable threatIntel={result.threatIntel} /> : null}
        {activeTab === "website" ? <WebsitePanel websiteIntel={result.websiteIntel} /> : null}
        {activeTab === "raw" ? (
          <pre className="max-h-64 overflow-auto rounded-xl border border-white/8 bg-bg p-4 font-data text-[11px] leading-5 text-green-400/80">
            {JSON.stringify(result.raw, null, 2)}
          </pre>
        ) : null}
      </div>
    </motion.section>
  );
}
