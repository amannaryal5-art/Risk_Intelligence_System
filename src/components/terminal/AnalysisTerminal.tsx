"use client";

import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown, ChevronRight } from "lucide-react";
import { useEffect, useRef } from "react";

import type { TerminalEntry } from "@/types/analysis";
import { cn } from "@/lib/utils";

function toneClass(tone: TerminalEntry["tone"]) {
  if (tone === "danger") return "text-danger/80";
  if (tone === "warning") return "text-warning/80";
  if (tone === "success") return "text-success/80";
  return "text-accent/80";
}

export function AnalysisTerminal({
  entries,
  open,
  onToggle,
}: {
  entries: TerminalEntry[];
  open: boolean;
  onToggle: () => void;
}) {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
  }, [entries]);

  return (
    <div className="overflow-hidden rounded-2xl border border-white/8 bg-[#020508]">
      <div className="flex items-center gap-3 border-b border-white/8 px-4 py-2">
        <div className="flex gap-1.5">
          <div className="h-3 w-3 rounded-full bg-danger/80" />
          <div className="h-3 w-3 rounded-full bg-warning/80" />
          <div className="h-3 w-3 rounded-full bg-success/80" />
        </div>
        <span className="font-data text-[11px] uppercase tracking-[0.2em] text-muted">
          Analysis Terminal
        </span>
        <button onClick={onToggle} className="ml-auto text-muted transition-colors hover:text-white">
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
      </div>

      <AnimatePresence initial={false}>
        {open ? (
          <motion.div
            initial={{ height: 0 }}
            animate={{ height: "auto" }}
            exit={{ height: 0 }}
            className="max-h-52 overflow-y-auto px-4 py-3 font-data text-xs leading-6"
            ref={ref}
          >
            {entries.length ? (
              entries.map((entry) => (
                <div key={entry.id} className={cn(toneClass(entry.tone))}>
                  <span className="select-none text-muted/40">
                    {new Date(entry.timestamp).toLocaleTimeString()}{" "}
                  </span>
                  {entry.message}
                </div>
              ))
            ) : (
              <div className="text-muted">No terminal events yet.</div>
            )}
            <span className="inline-block h-4 w-2 animate-blink bg-accent/70" />
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}
