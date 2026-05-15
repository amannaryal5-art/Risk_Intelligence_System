"use client";

import { useEffect, useState } from "react";
import { Radar, ShieldAlert, Sparkles } from "lucide-react";

import { Button } from "@/components/ui/button";
import { FileDropZone } from "@/components/input/FileDropZone";
import { TypeBadge } from "@/components/input/TypeBadge";
import { detectInputType } from "@/lib/detectInputType";
import type { InputType } from "@/types/analysis";

export function SmartInput({
  value,
  onChange,
  onAnalyze,
  isAnalyzing,
  autopilot,
  onAutopilotChange,
  file,
  onFileChange,
}: {
  value: string;
  onChange: (value: string) => void;
  onAnalyze: () => void;
  isAnalyzing: boolean;
  autopilot: boolean;
  onAutopilotChange: (value: boolean) => void;
  file: File | null;
  onFileChange: (file: File | null) => void;
}) {
  const [detectedType, setDetectedType] = useState<InputType>(detectInputType(value));
  const [dragging, setDragging] = useState(false);

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

  return (
    <section className="relative overflow-hidden rounded-[2rem] border border-accent/15 bg-[linear-gradient(160deg,rgba(10,18,27,0.96),rgba(8,13,20,0.98))] p-6 shadow-[0_0_0_1px_rgba(255,255,255,0.02),0_30px_80px_rgba(0,0,0,0.35)] lg:p-8">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(0,229,255,0.12),transparent_35%),radial-gradient(circle_at_bottom_right,rgba(124,58,237,0.1),transparent_25%)]" />
      <div className="relative space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="space-y-3">
            <div className="font-data text-xs uppercase tracking-[0.3em] text-accent/80">
              Unified Threat Intake
            </div>
            <h1 className="max-w-3xl font-heading text-4xl font-semibold uppercase tracking-[0.08em] text-white lg:text-6xl">
              Paste anything. Run a full SOC triage in one shot.
            </h1>
            <p className="max-w-2xl font-data text-sm leading-6 text-slate-300">
              URLs, IPs, domains, hashes, suspicious emails, multi-line reports, or a dropped file all funnel through one analysis surface.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <TypeBadge type={detectedType} />
            <label className="inline-flex cursor-pointer items-center gap-3 rounded-full border border-white/10 bg-white/[0.03] px-4 py-2 font-data text-xs uppercase tracking-[0.2em] text-slate-200">
              <span className={autopilot ? "text-accent" : "text-muted"}>Autopilot</span>
              <button
                type="button"
                aria-pressed={autopilot}
                onClick={() => onAutopilotChange(!autopilot)}
                className={`relative h-7 w-14 rounded-full border transition-colors ${
                  autopilot
                    ? "border-accent/30 bg-accent/20"
                    : "border-white/10 bg-black/20"
                }`}
              >
                <span
                  className={`absolute top-1 h-5 w-5 rounded-full transition-all ${
                    autopilot ? "left-8 bg-accent" : "left-1 bg-slate-400"
                  }`}
                />
              </button>
            </label>
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
          <div
            className="space-y-4 rounded-[1.6rem] border border-white/8 bg-black/20 p-4"
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
            <textarea
              id="riskintel-smart-input"
              value={value}
              onChange={(event) => onChange(event.target.value)}
              placeholder="Paste an IOC, a suspicious email, a URL, a report excerpt, or a batch list..."
              className="min-h-[220px] w-full resize-none rounded-[1.25rem] border border-white/10 bg-[#060b12] px-4 py-4 font-data text-sm text-slate-100 outline-none transition focus:border-accent/40"
            />
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="font-data text-xs uppercase tracking-[0.18em] text-muted">
                Shortcuts: Ctrl+Enter analyze, Ctrl+K focus, Escape clears result panel
              </div>
              <div className="flex flex-wrap gap-3">
                <Button variant="outline" onClick={() => onFileChange(null)}>
                  Clear File
                </Button>
                <Button onClick={onAnalyze} disabled={isAnalyzing || (!value.trim() && !file)}>
                  {isAnalyzing ? <Radar className="h-4 w-4 animate-spin" /> : <ShieldAlert className="h-4 w-4" />}
                  <span>{isAnalyzing ? "Analyzing" : "Analyze"}</span>
                </Button>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <FileDropZone file={file} dragging={dragging} />
            <label className="block">
              <input
                type="file"
                className="hidden"
                onChange={(event) => onFileChange(event.target.files?.[0] ?? null)}
              />
              <div className="cursor-pointer rounded-2xl border border-accent/15 bg-accent/5 px-4 py-4 font-data text-xs uppercase tracking-[0.22em] text-accent transition hover:bg-accent/10">
                Choose file from disk
              </div>
            </label>
            <div className="rounded-2xl border border-white/8 bg-black/20 p-4">
              <div className="mb-2 flex items-center gap-2 font-data text-xs uppercase tracking-[0.2em] text-accent">
                <Sparkles className="h-4 w-4" />
                Autopilot Flow
              </div>
              <div className="space-y-2 font-data text-sm text-slate-300">
                <div>Text: risk engine + IOC extraction in parallel.</div>
                <div>URL: website intel + threat intel + trace website.</div>
                <div>Score 70+: auto-create a case when your API role allows it.</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
