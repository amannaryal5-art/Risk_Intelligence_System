"use client";

import { motion } from "framer-motion";
import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { detectInputType } from "@/lib/detectInputType";
import { cn } from "@/lib/utils";
import { runAnalysis } from "@/lib/analyze";
import type { UnifiedAnalysisResult } from "@/types/analysis";

const typeColors: Record<string, string> = {
  ip: "text-accent border-accent/30 bg-accent/10",
  domain: "text-warning border-warning/30 bg-warning/10",
  url: "text-accent border-accent/30 bg-accent/10",
  hash_md5: "text-fuchsia-300 border-fuchsia-400/30 bg-fuchsia-400/10",
  hash_sha1: "text-fuchsia-300 border-fuchsia-400/30 bg-fuchsia-400/10",
  hash_sha256: "text-fuchsia-300 border-fuchsia-400/30 bg-fuchsia-400/10",
  email: "text-warning border-warning/30 bg-warning/10",
  text: "text-muted border-white/20 bg-white/5",
  batch: "text-success border-success/30 bg-success/10",
};

const verdictStyles: Record<string, string> = {
  SAFE: "border-success/40 bg-success/10 text-success",
  CAUTION: "border-warning/40 bg-warning/10 text-warning",
  DANGER: "border-danger/40 bg-danger/10 text-danger",
  CRITICAL: "border-danger/60 bg-danger/15 text-danger",
};

export default function BatchPage() {
  const [apiKey, setApiKey] = useState("");
  const [input, setInput] = useState("");
  const [results, setResults] = useState<UnifiedAnalysisResult[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [done, setDone] = useState(0);

  const lines = useMemo(
    () => input.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).slice(0, 100),
    [input],
  );

  const runBatch = async () => {
    setIsRunning(true);
    setDone(0);
    try {
      const next: UnifiedAnalysisResult[] = [];
      for (const [index, line] of lines.entries()) {
        next.push(await runAnalysis(line, apiKey, false));
        setDone(index + 1);
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
    <main className="min-h-screen bg-bg px-4 pb-8 pt-24 text-white lg:px-8">
      <div className="mx-auto max-w-7xl space-y-6">
        <div className="flex items-end justify-between gap-4">
          <div>
            <div className="font-data text-xs uppercase tracking-[0.28em] text-accent">Batch Intel</div>
            <div className="mt-2 font-heading text-4xl uppercase tracking-[0.08em] text-white">
              Run up to 100 indicators in one sweep
            </div>
          </div>
          <div className="rounded-full border border-white/10 bg-white/[0.03] px-4 py-2 font-data text-xs uppercase tracking-[0.2em] text-muted">
            {lines.length} targets
          </div>
        </div>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          <section className="rounded-2xl border border-accent/15 bg-gradient-to-b from-surface to-panel p-6">
            <textarea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder="One IP, domain, URL, hash, or text item per line"
              className="min-h-[360px] w-full rounded-xl border border-white/10 bg-bg/60 px-4 py-4 font-data text-xs text-slate-100 outline-none transition-all duration-150 focus:border-accent/40 focus:ring-2 focus:ring-accent/20"
            />

            <div className="mt-2 flex items-center justify-between">
              <span className="font-data text-[11px] text-muted">
                {input.length} chars · {lines.length} targets
              </span>
              <input
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                placeholder="X-API-Key"
                className="rounded-xl border border-white/10 bg-[#060b12] px-3 py-2 font-data text-xs text-slate-100 outline-none transition-all duration-150 focus:border-accent/40"
              />
            </div>

            {isRunning && lines.length ? (
              <div className="my-4 space-y-2">
                <div className="flex justify-between font-data text-[11px] text-muted">
                  <span>
                    Processing {done}/{lines.length}
                  </span>
                  <span>{Math.round((done / lines.length) * 100)}%</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-white/8">
                  <motion.div
                    className="h-full rounded-full bg-gradient-to-r from-accent to-success"
                    animate={{ width: `${(done / lines.length) * 100}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>
              </div>
            ) : null}

            <div className="mt-4 flex flex-wrap gap-3">
              <Button onClick={runBatch} disabled={!lines.length || isRunning}>
                {isRunning ? "Running Batch" : "Run Batch"}
              </Button>
              <Button variant="outline" onClick={exportCsv} disabled={!results.length}>
                Export CSV
              </Button>
            </div>
          </section>

          <section className="overflow-hidden rounded-2xl border border-white/8 bg-surface/80 p-5">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/8">
                  <th className="py-2 text-left font-data text-[10px] uppercase tracking-[0.28em] text-muted">Input</th>
                  <th className="py-2 text-left font-data text-[10px] uppercase tracking-[0.28em] text-muted">Type</th>
                  <th className="py-2 text-right font-data text-[10px] uppercase tracking-[0.28em] text-muted">Score</th>
                  <th className="py-2 text-right font-data text-[10px] uppercase tracking-[0.28em] text-muted">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {results.map((item, index) => (
                  <motion.tr
                    key={`${item.type}-${item.input}`}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.03 }}
                    className="border-b border-white/5 hover:bg-white/[0.02]"
                  >
                    <td className="max-w-[220px] truncate py-2.5 font-data text-xs text-slate-300">{item.input}</td>
                    <td className="py-2.5">
                      <span
                        className={cn(
                          "rounded-full border px-2 py-0.5 font-data text-[10px] uppercase",
                          typeColors[detectInputType(item.input)],
                        )}
                      >
                        {detectInputType(item.input)}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      <span
                        className={cn(
                          "font-heading text-lg font-bold",
                          item.score >= 70 ? "text-danger" : item.score >= 30 ? "text-warning" : "text-success",
                        )}
                      >
                        {item.score}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      <span
                        className={cn(
                          "rounded-full border px-2.5 py-1 font-data text-[10px] uppercase tracking-[0.18em]",
                          verdictStyles[item.verdict],
                        )}
                      >
                        {item.verdict}
                      </span>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </section>
        </div>
      </div>
    </main>
  );
}
