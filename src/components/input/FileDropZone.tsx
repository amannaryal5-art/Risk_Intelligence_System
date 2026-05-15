"use client";

import { Upload } from "lucide-react";

import { cn } from "@/lib/utils";

export function FileDropZone({
  file,
  dragging,
}: {
  file: File | null;
  dragging: boolean;
}) {
  return (
    <div
      className={cn(
        "rounded-2xl border border-dashed px-4 py-5 transition-colors",
        dragging ? "border-accent bg-accent/10" : "border-white/10 bg-black/20",
      )}
    >
      <div className="flex items-center gap-3">
        <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-accent/20 bg-accent/10 text-accent">
          <Upload className="h-5 w-5" />
        </div>
        <div>
          <div className="font-heading text-lg uppercase tracking-[0.08em] text-white">
            {file ? file.name : "Drop sample for malware triage"}
          </div>
          <div className="font-data text-xs uppercase tracking-[0.18em] text-muted">
            {file ? "File queued for analysis" : "Supports scripts, archives, office docs, and binaries"}
          </div>
        </div>
      </div>
    </div>
  );
}
