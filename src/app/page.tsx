"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { CaseCard } from "@/components/cases/CaseCard";
import { CaseModal } from "@/components/cases/CaseModal";
import { FeedHealthBar } from "@/components/feeds/FeedHealthBar";
import { SmartInput } from "@/components/input/SmartInput";
import { ResultsPanel } from "@/components/results/ResultsPanel";
import { AnalysisTerminal } from "@/components/terminal/AnalysisTerminal";
import { useAnalysis } from "@/hooks/useAnalysis";
import { useCases } from "@/hooks/useCases";
import { useScanHistory } from "@/hooks/useScanHistory";
import type { RiskCase } from "@/types/cases";

function scoreTone(score: number) {
  if (score >= 84) return "bg-danger/15 text-danger border-danger/30";
  if (score >= 66) return "bg-warning/15 text-warning border-warning/30";
  if (score >= 35) return "bg-accent/10 text-accent border-accent/30";
  return "bg-success/10 text-success border-success/30";
}

export default function HomePage() {
  const [apiKey, setApiKey] = useState("");
  const [input, setInput] = useState("");
  const [autopilot, setAutopilot] = useState(true);
  const [file, setFile] = useState<File | null>(null);
  const [terminalOpen, setTerminalOpen] = useState(true);
  const [selectedCase, setSelectedCase] = useState<RiskCase | null>(null);
  const { result, setResult, isAnalyzing, terminalEntries, error, analyze } = useAnalysis();
  const { history, addHistory } = useScanHistory();
  const { cases, refresh: refreshCases } = useCases(apiKey, 5);

  useEffect(() => {
    const stored = window.localStorage.getItem("riskintel_api_key")?.trim() ?? "";
    setApiKey(stored);
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

  const analysisStages = useMemo(() => {
    if (!isAnalyzing) return [];
    return [
      "Classifying input",
      autopilot ? "Launching autopilot pipeline" : "Running targeted scan",
      "Collecting live feed hits",
      "Merging analyst-ready report",
    ];
  }, [autopilot, isAnalyzing]);

  const handleAnalyze = async () => {
    const next = await analyze({ input, apiKey, autopilot, file });
    addHistory(next);
    setFile(null);
    refreshCases().catch(() => null);
  };

  const saveApiKey = (value: string) => {
    setApiKey(value);
    window.localStorage.setItem("riskintel_api_key", value);
  };

  return (
    <main className="min-h-screen bg-bg px-4 py-6 text-white lg:px-8">
      <div className="mx-auto max-w-[1500px] space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-2">
            <div className="font-data text-xs uppercase tracking-[0.3em] text-accent">RiskIntel v3.0</div>
            <div className="font-heading text-3xl uppercase tracking-[0.08em] text-white lg:text-5xl">
              Autonomous cyber risk command deck
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <FeedHealthBar apiKey={apiKey} />
            <Link href="/batch" className="rounded-full border border-white/10 px-4 py-3 font-data text-xs uppercase tracking-[0.18em] text-slate-200">
              Batch
            </Link>
            <Link href="/cases" className="rounded-full border border-white/10 px-4 py-3 font-data text-xs uppercase tracking-[0.18em] text-slate-200">
              Cases
            </Link>
            <Link href="/scamcheck" className="rounded-full border border-white/10 px-4 py-3 font-data text-xs uppercase tracking-[0.18em] text-slate-200">
              Scamcheck
            </Link>
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
          <div className="space-y-6">
            <SmartInput
              value={input}
              onChange={setInput}
              onAnalyze={handleAnalyze}
              isAnalyzing={isAnalyzing}
              autopilot={autopilot}
              onAutopilotChange={setAutopilot}
              file={file}
              onFileChange={setFile}
            />

            {isAnalyzing ? (
              <section className="rounded-2xl border border-accent/15 bg-black/30 p-5">
                <div className="mb-4 font-data text-xs uppercase tracking-[0.22em] text-accent">
                  Analysis Pipeline
                </div>
                <div className="grid gap-3 lg:grid-cols-4">
                  {analysisStages.map((stage, index) => (
                    <div key={stage} className="rounded-xl border border-white/8 bg-white/[0.03] p-4">
                      <div className="font-data text-xs uppercase tracking-[0.18em] text-muted">Stage {index + 1}</div>
                      <div className="mt-2 font-heading text-lg uppercase tracking-[0.05em] text-white">{stage}</div>
                    </div>
                  ))}
                </div>
              </section>
            ) : null}

            {result ? <ResultsPanel result={result} /> : null}

            <AnalysisTerminal entries={terminalEntries} open={terminalOpen} />
            {error ? <div className="rounded-xl border border-danger/20 bg-danger/10 p-4 font-data text-sm text-danger">{error}</div> : null}
          </div>

          <aside className="space-y-6">
            <section className="rounded-2xl border border-white/8 bg-black/20 p-5">
              <div className="mb-3 font-data text-xs uppercase tracking-[0.24em] text-accent">Settings</div>
              <label className="block font-data text-xs uppercase tracking-[0.18em] text-muted">
                API key
                <input
                  value={apiKey}
                  onChange={(event) => saveApiKey(event.target.value)}
                  placeholder="Paste X-API-Key"
                  className="mt-2 w-full rounded-xl border border-white/10 bg-[#060b12] px-3 py-3 text-sm text-slate-100 outline-none focus:border-accent/35"
                />
              </label>
              <div className="mt-3 font-data text-xs text-muted">
                Stored in localStorage as <code>riskintel_api_key</code>.
              </div>
            </section>

            <section className="rounded-2xl border border-white/8 bg-black/20 p-5">
              <div className="mb-4 flex items-center justify-between">
                <div className="font-data text-xs uppercase tracking-[0.24em] text-accent">Recent Scans</div>
                <div className="font-data text-xs uppercase tracking-[0.18em] text-muted">Last 10</div>
              </div>
              <div className="space-y-3">
                {history.slice(0, 5).map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setInput(item.input)}
                    className={`w-full rounded-xl border px-4 py-3 text-left ${scoreTone(item.score)}`}
                  >
                    <div className="truncate font-data text-xs uppercase tracking-[0.18em]">{item.type}</div>
                    <div className="mt-1 truncate font-heading text-lg uppercase tracking-[0.05em]">{item.input}</div>
                  </button>
                ))}
              </div>
            </section>

            <section className="rounded-2xl border border-white/8 bg-black/20 p-5">
              <div className="mb-4 font-data text-xs uppercase tracking-[0.24em] text-accent">Recent Cases</div>
              <div className="space-y-3">
                {cases.slice(0, 3).map((item) => (
                  <CaseCard key={item.id} item={item} onOpen={setSelectedCase} />
                ))}
              </div>
            </section>
          </aside>
        </div>
      </div>

      <CaseModal item={selectedCase} onClose={() => setSelectedCase(null)} />
    </main>
  );
}
