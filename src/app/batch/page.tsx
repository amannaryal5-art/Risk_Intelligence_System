"use client";

import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { detectInputType } from "@/lib/detectInputType";
import { runAnalysis } from "@/lib/analyze";
import type { UnifiedAnalysisResult } from "@/types/analysis";

export default function BatchPage() {
  const [apiKey, setApiKey] = useState("");
  const [input, setInput] = useState("");
  const [results, setResults] = useState<UnifiedAnalysisResult[]>([]);
  const [isRunning, setIsRunning] = useState(false);

  const lines = useMemo(
    () => input.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).slice(0, 100),
    [input],
  );

  const runBatch = async () => {
    setIsRunning(true);
    try {
      const next: UnifiedAnalysisResult[] = [];
      for (const line of lines) {
        next.push(await runAnalysis(line, apiKey, false));
      }
      setResults(next);
    } finally {
      setIsRunning(false);
    }
  };

  const exportCsv = () => {
    const rows = [
      ["input", "type", "score", "verdict", "summary"],
      ...results.map((item) => [item.input, item.type, String(item.score), item.verdict, item.summary]),
    ];
    const csv = rows.map((row) => row.map((cell) => `"${cell.replaceAll('"', '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "riskintel-batch-results.csv";
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <main className="min-h-screen bg-bg px-4 py-6 text-white lg:px-8">
      <div className="mx-auto max-w-6xl space-y-6">
        <div>
          <div className="font-data text-xs uppercase tracking-[0.28em] text-accent">Batch Analysis</div>
          <div className="mt-2 font-heading text-4xl uppercase tracking-[0.08em] text-white">
            Run up to 100 indicators in sequence
          </div>
        </div>

        <section className="rounded-[2rem] border border-accent/15 bg-black/20 p-6">
          <div className="grid gap-4 lg:grid-cols-[1fr_240px]">
            <textarea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder="One IP, domain, URL, hash, or text item per line"
              className="min-h-[280px] w-full rounded-2xl border border-white/10 bg-[#060b12] px-4 py-4 font-data text-sm text-slate-100 outline-none focus:border-accent/35"
            />
            <div className="space-y-4">
              <input
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                placeholder="X-API-Key"
                className="w-full rounded-xl border border-white/10 bg-[#060b12] px-3 py-3 font-data text-sm text-slate-100 outline-none focus:border-accent/35"
              />
              <Button onClick={runBatch} disabled={!lines.length || isRunning}>
                <span>{isRunning ? "Running" : "Run Batch"}</span>
              </Button>
              <Button variant="outline" onClick={exportCsv} disabled={!results.length}>
                Export CSV
              </Button>
              <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-4 font-data text-sm text-slate-300">
                {lines.length} queued
              </div>
            </div>
          </div>
        </section>

        <section className="overflow-hidden rounded-[2rem] border border-white/8">
          <table className="w-full border-collapse font-data text-sm">
            <thead className="bg-white/[0.03] text-left text-xs uppercase tracking-[0.18em] text-muted">
              <tr>
                <th className="px-4 py-3">Input</th>
                <th className="px-4 py-3">Detected Type</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Verdict</th>
                <th className="px-4 py-3">Top Signal</th>
              </tr>
            </thead>
            <tbody>
              {results.map((item) => (
                <tr key={`${item.type}-${item.input}`} className="border-t border-white/6 text-slate-200">
                  <td className="px-4 py-3">{item.input}</td>
                  <td className="px-4 py-3">{detectInputType(item.input)}</td>
                  <td className="px-4 py-3">{item.score}</td>
                  <td className="px-4 py-3">{item.verdict}</td>
                  <td className="px-4 py-3">{item.signals[0]?.detail ?? item.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </main>
  );
}
