"use client";

import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { Check, Radar, ShieldAlert, Sparkles } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { FileDropZone } from "@/components/input/FileDropZone";
import { TypeBadge } from "@/components/input/TypeBadge";
import { Spinner } from "@/components/shared/Spinner";
import { Button } from "@/components/ui/button";
import { detectInputType, labelForInputType } from "@/lib/detectInputType";
import { cn } from "@/lib/utils";
import type { InputType } from "@/types/analysis";
import type { ScanHistoryItem } from "@/hooks/useScanHistory";

const typeColors: Record<InputType, string> = {
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

export function SmartInput({
  value,
  onChange,
  onAnalyze,
  onClear,
  isAnalyzing,
  autopilot,
  onAutopilotChange,
  file,
  onFileChange,
  history,
  pipelineSteps,
}: {
  value: string;
  onChange: (value: string) => void;
  onAnalyze: () => void;
  onClear: () => void;
  isAnalyzing: boolean;
  autopilot: boolean;
  onAutopilotChange: (value: boolean) => void;
  file: File | null;
  onFileChange: (file: File | null) => void;
  history: ScanHistoryItem[];
  pipelineSteps: Array<{ id: string; label: string; status: "done" | "active" | "pending" }>;
}) {
  const reducedMotion = useReducedMotion();
  const [detectedType, setDetectedType] = useState<InputType>(detectInputType(value));
  const [dragging, setDragging] = useState(false);
  const [focused, setFocused] = useState(false);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDetectedType(detectInputType(value));
    }, 300);
    return () => window.clearTimeout(timer);
  }, [value]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.ctrlKey && event.key === "Enter") {
        event.preventDefault();
        onAnalyze();
      }
      if (event.ctrlKey && event.key.toLowerCase() === "k") {
        event.preventDefault();
        const area = document.getElementById("riskintel-smart-input");
        if (area instanceof HTMLTextAreaElement) {
          area.focus();
          area.select();
        }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onAnalyze]);

  const extracted = useMemo(() => {
    const urls = value.match(/https?:\/\/[^\s]+/g) ?? [];
    const ips = value.match(/\b(\d{1,3}\.){3}\d{1,3}\b/g) ?? [];
    const hashes = [
      ...(value.match(/\b[a-fA-F0-9]{32}\b/g) ?? []),
      ...(value.match(/\b[a-fA-F0-9]{40}\b/g) ?? []),
      ...(value.match(/\b[a-fA-F0-9]{64}\b/g) ?? []),
    ];
    const domains =
      value.match(/\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b/g)?.filter((entry) => !urls.some((url) => url.includes(entry))) ??
      [];
    return [...new Set([...urls, ...ips, ...domains, ...hashes])].slice(0, 12);
  }, [value]);

  const lineCount = value.split(/\r?\n/).filter((line) => line.trim()).length;

  return (
    <section className="rounded-2xl border border-accent/15 bg-gradient-to-b from-surface to-panel p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-accent/20 bg-accent/10">
            <Radar className="h-5 w-5 animate-[spin_10s_linear_infinite] text-accent" />
          </div>
          <div>
            <div className="font-heading text-xl font-semibold uppercase tracking-[0.1em] text-white">
              Threat Intake Console
            </div>
            <div className="font-data text-[11px] uppercase tracking-[0.28em] text-muted">
              Universal IOC Analysis
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={() => onAutopilotChange(!autopilot)}
          className={cn(
            "flex items-center gap-2 rounded-full border px-4 py-2 font-data text-xs uppercase tracking-[0.2em] transition-all duration-300",
            autopilot
              ? "border-accent/40 bg-accent/10 text-accent shadow-cyan-glow"
              : "border-white/20 bg-white/5 text-muted hover:border-white/30 hover:text-white",
          )}
        >
          <span
            className={cn(
              "h-2 w-2 rounded-full transition-colors duration-300",
              autopilot ? "bg-accent animate-pulse" : "bg-muted",
            )}
          />
          Autopilot {autopilot ? "ON" : "OFF"}
        </button>
      </div>

      <div
        className="space-y-4"
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          const dropped = event.dataTransfer.files?.[0];
          if (dropped) onFileChange(dropped);
        }}
      >
        {dragging ? <FileDropZone file={file} dragging={dragging} /> : null}

        {!dragging ? (
          <div className="relative">
            <textarea
              id="riskintel-smart-input"
              value={value}
              onChange={(event) => onChange(event.target.value)}
              onFocus={() => setFocused(true)}
              onBlur={() => setFocused(false)}
              placeholder="Paste any threat indicator: IP, domain, URL, hash, email, suspicious message, or drop a file..."
              rows={5}
              className={cn(
                "w-full resize-none rounded-xl border bg-bg/60 px-4 py-4 font-data text-sm text-slate-200 placeholder:text-muted transition-all duration-200",
                focused
                  ? "border-accent/40 ring-1 ring-accent/20 shadow-[0_0_0_3px_rgba(0,212,255,0.06)]"
                  : "border-white/10 hover:border-white/20",
              )}
            />
            <AnimatePresence>
              {value.length > 2 ? (
                <motion.div
                  key={detectedType}
                  initial={reducedMotion ? false : { opacity: 0, scale: 0.8, y: -4 }}
                  animate={reducedMotion ? undefined : { opacity: 1, scale: 1, y: 0 }}
                  exit={reducedMotion ? undefined : { opacity: 0, scale: 0.8, y: -4 }}
                  className={cn(
                    "absolute right-3 top-3 rounded-full border px-2.5 py-1 font-data text-[10px] uppercase tracking-[0.2em]",
                    typeColors[detectedType],
                  )}
                >
                  {labelForInputType(detectedType)}
                </motion.div>
              ) : null}
            </AnimatePresence>
          </div>
        ) : null}

        <AnimatePresence>
          {extracted.length > 0 ? (
            <motion.div
              initial={reducedMotion ? false : { opacity: 0, height: 0 }}
              animate={reducedMotion ? undefined : { opacity: 1, height: "auto" }}
              exit={reducedMotion ? undefined : { opacity: 0, height: 0 }}
              className="rounded-xl border border-accent/20 bg-accent/5 p-3"
            >
              <div className="mb-2 font-data text-[10px] uppercase tracking-[0.28em] text-muted">
                Detected Indicators
              </div>
              <div className="flex flex-wrap gap-1.5">
                {extracted.map((ioc) => (
                  <span
                    key={ioc}
                    className="rounded-md border border-accent/25 bg-panel px-2 py-0.5 font-data text-[11px] text-accent"
                  >
                    {ioc}
                  </span>
                ))}
              </div>
            </motion.div>
          ) : null}
        </AnimatePresence>

        <div className="flex items-center justify-between">
          <span className="font-data text-[11px] text-muted">
            {value.length} chars{detectedType === "batch" ? ` · ${lineCount} targets` : ""}
          </span>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onClear}
              className="font-data text-[11px] uppercase tracking-[0.18em] text-muted transition-colors hover:text-white"
            >
              Clear
            </button>
            <kbd className="rounded border border-white/15 bg-white/5 px-1.5 py-0.5 font-data text-[10px] text-muted">
              Ctrl+Enter
            </kbd>
          </div>
        </div>

        <div className="flex flex-wrap gap-3">
          <label className="block">
            <input
              type="file"
              className="hidden"
              onChange={(event) => onFileChange(event.target.files?.[0] ?? null)}
            />
            <div className="cursor-pointer rounded-xl border border-white/15 bg-white/[0.03] px-4 py-3 font-data text-[11px] uppercase tracking-[0.22em] text-muted transition-all duration-150 hover:border-white/25 hover:text-white">
              {file ? `${file.name}` : "Drop artifact or click to upload"}
            </div>
          </label>
          {file ? <TypeBadge type="text" /> : null}
        </div>

        <button
          type="button"
          disabled={isAnalyzing || (!value.trim() && !file)}
          onClick={onAnalyze}
          className={cn(
            "mt-1 w-full rounded-xl border py-3.5 font-heading text-sm font-semibold uppercase tracking-[0.14em] transition-all duration-200 active:scale-[0.99]",
            isAnalyzing
              ? "border-accent/20 bg-accent/5 text-accent/60"
              : "border-accent/30 bg-accent/10 text-accent shadow-[0_0_0_1px_rgba(0,212,255,0.08)] hover:bg-accent/20 hover:shadow-cyan-glow",
          )}
        >
          <div className="flex items-center justify-center gap-2">
            {isAnalyzing ? <Spinner /> : <ShieldAlert className="h-4 w-4" />}
            <span className={isAnalyzing ? "animate-pulse" : ""}>{isAnalyzing ? "Analyzing..." : "Analyze"}</span>
          </div>
        </button>

        {autopilot && pipelineSteps.length > 0 ? (
          <div className="mt-3 flex items-center gap-2">
            {pipelineSteps.map((step, index) => (
              <div key={step.id} className="contents">
                <div
                  className={cn(
                    "flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-data text-[10px] uppercase tracking-[0.18em] transition-all duration-300",
                    step.status === "done" && "border-success/30 bg-success/10 text-success",
                    step.status === "active" && "border-accent/40 bg-accent/10 text-accent",
                    step.status === "pending" && "border-white/10 bg-transparent text-muted",
                  )}
                >
                  {step.status === "done" ? (
                    <Check className="h-3 w-3" />
                  ) : step.status === "active" ? (
                    <span className="h-2 w-2 rounded-full bg-accent animate-pulse" />
                  ) : (
                    <span className="h-2 w-2 rounded-full bg-muted/40" />
                  )}
                  {step.label}
                </div>
                {index < pipelineSteps.length - 1 ? (
                  <div
                    className={cn(
                      "h-px flex-1 transition-colors duration-500",
                      step.status === "done" ? "bg-success/40" : "bg-white/10",
                    )}
                  />
                ) : null}
              </div>
            ))}
          </div>
        ) : null}

        <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
          <div className="mb-2 flex items-center gap-2 font-data text-[10px] uppercase tracking-[0.28em] text-muted">
            <Sparkles className="h-4 w-4 text-accent" />
            Autopilot profile
          </div>
          <div className="space-y-2 font-data text-xs leading-6 text-slate-300">
            <div>Text: risk engine plus IOC enrichment in parallel.</div>
            <div>URL: website intel, threat intel, and site trace merge into one report.</div>
            <div>Score 70+: case creation can fire automatically for analyst-capable keys.</div>
          </div>
        </div>

        <div className="space-y-2">
          <div className="font-data text-[10px] uppercase tracking-[0.28em] text-muted">Recent</div>
          <div className="flex flex-wrap gap-2">
            {history.slice(0, 5).map((item) => (
              <button
                key={item.id}
                onClick={() => onChange(item.input)}
                className="group flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 font-data text-[11px] transition-all hover:border-accent/30 hover:bg-accent/5"
              >
                <span
                  className={cn(
                    "h-1.5 w-1.5 rounded-full",
                    item.score >= 70 ? "bg-danger" : item.score >= 30 ? "bg-warning" : "bg-success",
                  )}
                />
                <span className="max-w-[140px] truncate text-muted transition-colors group-hover:text-white">
                  {item.input}
                </span>
                <span
                  className={cn(
                    "shrink-0 font-semibold",
                    item.score >= 70 ? "text-danger" : item.score >= 30 ? "text-warning" : "text-success",
                  )}
                >
                  {item.score}
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
