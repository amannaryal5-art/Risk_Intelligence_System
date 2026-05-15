"use client";

import { useEffect, useRef } from "react";

import type { TerminalEntry } from "@/types/analysis";

function toneClass(tone: TerminalEntry["tone"]) {
  if (tone === "danger") return "text-danger";
  if (tone === "warning") return "text-warning";
  if (tone === "success") return "text-success";
  return "text-accent/80";
}

export function AnalysisTerminal({
  entries,
  open,
}: {
  entries: TerminalEntry[];
  open: boolean;
}) {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
  }, [entries]);

  if (!open) return null;

  return (
    <section className="rounded-[1.5rem] border border-accent/15 bg-black/50 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
      <div className="mb-3 font-data text-xs uppercase tracking-[0.24em] text-accent">
        Streaming Terminal
      </div>
      <div
        ref={ref}
        className="max-h-[260px] space-y-2 overflow-auto rounded-xl border border-white/8 bg-[#04070b] p-4 font-data text-xs"
      >
        {entries.length ? (
          entries.map((entry) => (
            <div key={entry.id} className={toneClass(entry.tone)}>
              [{new Date(entry.timestamp).toLocaleTimeString()}] {entry.message}
            </div>
          ))
        ) : (
          <div className="text-muted">No terminal events yet.</div>
        )}
      </div>
    </section>
  );
}
