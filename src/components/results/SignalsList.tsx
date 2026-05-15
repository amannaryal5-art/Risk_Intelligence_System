import type { AnalysisSignal } from "@/types/analysis";

export function SignalsList({ signals }: { signals: AnalysisSignal[] }) {
  return (
    <div className="space-y-3">
      {signals.length ? (
        signals.slice(0, 8).map((signal) => (
          <div key={`${signal.name}-${signal.detail}`} className="rounded-xl border border-white/8 bg-black/20 p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="font-data text-sm uppercase tracking-[0.15em] text-slate-100">{signal.name}</div>
              <div className="font-data text-xs uppercase tracking-[0.18em] text-accent">
                {Math.round(signal.score * 100)} weight
              </div>
            </div>
            <div className="mt-2 font-data text-sm text-slate-300">{signal.detail}</div>
          </div>
        ))
      ) : (
        <div className="rounded-xl border border-white/8 bg-black/20 p-4 font-data text-sm text-muted">
          No weighted signals were returned for this result.
        </div>
      )}
    </div>
  );
}
