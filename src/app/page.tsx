"use client";

import { useEffect, useMemo, useState } from "react";

import { CaseCard } from "@/components/cases/CaseCard";
import { CaseModal } from "@/components/cases/CaseModal";
import { ResultsPanel } from "@/components/results/ResultsPanel";
import { AnalysisTerminal } from "@/components/terminal/AnalysisTerminal";
import { SmartInput } from "@/components/input/SmartInput";
import { useAnalysis } from "@/hooks/useAnalysis";
import { useCases } from "@/hooks/useCases";
import { useScanHistory } from "@/hooks/useScanHistory";
import type { RiskCase } from "@/types/cases";

export default function HomePage() {
  const [apiKey, setApiKey] = useState("");
  const [input, setInput] = useState("");
  const [autopilot, setAutopilot] = useState(true);
  const [file, setFile] = useState<File | null>(null);
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [selectedCase, setSelectedCase] = useState<RiskCase | null>(null);
  const { result, setResult, isAnalyzing, terminalEntries, error, analyze } = useAnalysis();
  const { history, addHistory } = useScanHistory();
  const { cases, refresh: refreshCases } = useCases(apiKey, 5);

  useEffect(() => {
    const stored = window.localStorage.getItem("riskintel_api_key")?.trim() ?? "";
    setApiKey(stored);
    setTerminalOpen(window.innerWidth >= 1280);
  }, []);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setResult(null);
      if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "t") {
        event.preventDefault();
        setTerminalOpen((current) => !current);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [setResult]);

  const pipelineSteps = useMemo(() => {
    if (!isAnalyzing) return [];
    return [
      { id: "detect", label: "Detect", status: "done" as const },
      { id: "analyze", label: "Analyze", status: "done" as const },
      { id: "intel", label: "Intel", status: "active" as const },
      { id: "fuse", label: "Fuse", status: "pending" as const },
    ];
  }, [isAnalyzing]);

  const handleAnalyze = async () => {
    const next = await analyze({ input, apiKey, autopilot, file });
    addHistory(next);
    setFile(null);
    refreshCases().catch(() => null);
  };

  const handleClear = () => {
    setInput("");
    setFile(null);
    setResult(null);
  };

  return (
    <main className="min-h-screen bg-bg px-4 pb-8 pt-24 text-white lg:px-8">
      <div className="mx-auto max-w-[1600px]">
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(360px,0.8fr)]">
          <div className="space-y-6">
            {!result && !isAnalyzing ? (
              <div className="flex flex-col items-center gap-3 py-12 text-center">
                <div className="relative">
                  <div className="absolute inset-0 rounded-full bg-accent/5 blur-xl" />
                  <div className="relative font-heading text-6xl text-accent/30">◎</div>
                </div>
                <div className="font-heading text-3xl font-semibold uppercase tracking-[0.1em] text-white/80">
                  Intelligence Ready
                </div>
                <div className="max-w-sm font-data text-sm text-muted">
                  Paste any suspicious indicator and get instant threat intelligence from 3 live feeds
                </div>
              </div>
            ) : null}

            <SmartInput
              value={input}
              onChange={setInput}
              onAnalyze={handleAnalyze}
              onClear={handleClear}
              isAnalyzing={isAnalyzing}
              autopilot={autopilot}
              onAutopilotChange={setAutopilot}
              file={file}
              onFileChange={setFile}
              history={history}
              pipelineSteps={pipelineSteps}
            />

            <AnalysisTerminal
              entries={terminalEntries}
              open={terminalOpen}
              onToggle={() => setTerminalOpen((current) => !current)}
            />

            {error ? (
              <div className="rounded-xl border border-danger/25 bg-danger/5 px-4 py-3">
                <div className="flex items-center gap-2">
                  <span className="text-danger">X</span>
                  <span className="font-data text-xs text-danger">{error}</span>
                </div>
              </div>
            ) : null}
          </div>

          <aside className="space-y-4 xl:sticky xl:top-[64px] xl:self-start">
            {result ? (
              <ResultsPanel result={result} />
            ) : (
              <section className="rounded-2xl border border-white/8 bg-white/[0.02] p-6">
                <div className="font-data text-[10px] uppercase tracking-[0.28em] text-muted">
                  Results Panel
                </div>
                <div className="mt-4 font-heading text-2xl uppercase tracking-[0.08em] text-white">
                  Awaiting first scan
                </div>
                <p className="mt-3 font-data text-sm leading-6 text-muted">
                  Your merged risk gauge, IOC feed hits, website intelligence, and raw analyst output will appear here.
                </p>
              </section>
            )}

            <section className="rounded-2xl border border-white/8 bg-surface/80 p-5">
              <div className="mb-4 font-data text-xs uppercase tracking-[0.24em] text-accent">
                Recent Cases
              </div>
              <div className="space-y-3">
                {cases.slice(0, 3).map((item) => (
                  <CaseCard key={item.id} item={item} onOpen={setSelectedCase} />
                ))}
              </div>
            </section>

            <section className="rounded-2xl border border-white/8 bg-surface/80 p-5">
              <div className="mb-3 font-data text-xs uppercase tracking-[0.24em] text-accent">
                API Console
              </div>
              <input
                value={apiKey}
                onChange={(event) => {
                  const next = event.target.value;
                  setApiKey(next);
                  window.localStorage.setItem("riskintel_api_key", next);
                }}
                placeholder="Paste X-API-Key"
                className="w-full rounded-xl border border-white/10 bg-[#060b12] px-3 py-3 font-data text-sm text-slate-100 outline-none transition-all duration-150 focus:border-accent/40 focus:ring-2 focus:ring-accent/20"
              />
            </section>
          </aside>
        </div>
      </div>

      <CaseModal item={selectedCase} onClose={() => setSelectedCase(null)} />
    </main>
  );
}
