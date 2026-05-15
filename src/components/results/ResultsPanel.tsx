"use client";

import { useState } from "react";

import { IOCTable } from "@/components/results/IOCTable";
import { RiskGauge } from "@/components/results/RiskGauge";
import { SignalsList } from "@/components/results/SignalsList";
import { VerdictBadge } from "@/components/results/VerdictBadge";
import { WebsitePanel } from "@/components/results/WebsitePanel";
import type { UnifiedAnalysisResult } from "@/types/analysis";

const tabs = ["signals", "ioc", "website", "raw"] as const;

export function ResultsPanel({ result }: { result: UnifiedAnalysisResult }) {
  const [activeTab, setActiveTab] = useState<(typeof tabs)[number]>("signals");

  return (
    <section className="rounded-[2rem] border border-accent/15 bg-[linear-gradient(180deg,rgba(10,16,24,0.98),rgba(7,12,19,0.98))] p-6 shadow-cyan-glow">
      <div className="grid gap-6 lg:grid-cols-[220px_1fr]">
        <div className="space-y-4">
          <RiskGauge score={result.score} />
          <VerdictBadge verdict={result.verdict} />
        </div>
        <div className="space-y-5">
          <div>
            <div className="font-data text-xs uppercase tracking-[0.24em] text-accent">
              Unified Report
            </div>
            <div className="mt-2 font-heading text-3xl uppercase tracking-[0.06em] text-white">
              {result.summary}
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
            {tabs.map((tab) => (
              <button
                key={tab}
                type="button"
                onClick={() => setActiveTab(tab)}
                className={`rounded-full border px-4 py-2 font-data text-xs uppercase tracking-[0.18em] transition ${
                  activeTab === tab
                    ? "border-accent/30 bg-accent/15 text-accent"
                    : "border-white/8 bg-white/[0.03] text-muted"
                }`}
              >
                {tab}
              </button>
            ))}
          </div>

          {activeTab === "signals" ? <SignalsList signals={result.signals} /> : null}
          {activeTab === "ioc" ? <IOCTable threatIntel={result.threatIntel} /> : null}
          {activeTab === "website" ? <WebsitePanel websiteIntel={result.websiteIntel} /> : null}
          {activeTab === "raw" ? (
            <pre className="max-h-[420px] overflow-auto rounded-2xl border border-white/8 bg-black/30 p-4 font-data text-xs text-slate-300">
              {JSON.stringify(result.raw, null, 2)}
            </pre>
          ) : null}
        </div>
      </div>
    </section>
  );
}
