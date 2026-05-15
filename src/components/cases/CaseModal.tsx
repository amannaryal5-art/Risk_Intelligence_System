"use client";

import { X } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { RiskCase } from "@/types/cases";

export function CaseModal({
  item,
  onClose,
}: {
  item: RiskCase | null;
  onClose: () => void;
}) {
  if (!item) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="max-h-[85vh] w-full max-w-3xl overflow-auto rounded-[2rem] border border-accent/15 bg-[#09111a] p-6">
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <div className="font-heading text-3xl uppercase tracking-[0.08em] text-white">{item.title}</div>
            <div className="mt-2 font-data text-sm text-muted">
              {item.status} | {item.severity} | Reporter {item.reporter}
            </div>
          </div>
          <Button variant="outline" onClick={onClose}>
            <X className="h-4 w-4" />
            <span>Close</span>
          </Button>
        </div>
        <pre className="overflow-auto rounded-2xl border border-white/8 bg-black/30 p-4 font-data text-xs text-slate-300">
          {JSON.stringify(item, null, 2)}
        </pre>
      </div>
    </div>
  );
}
