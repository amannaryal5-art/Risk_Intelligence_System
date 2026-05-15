import type { RiskCase } from "@/types/cases";
import { cn } from "@/lib/utils";

const severityBorder = {
  low: "border-l-success",
  medium: "border-l-warning",
  high: "border-l-danger",
  critical: "border-l-danger shadow-[0_0_20px_rgba(255,51,102,0.15)]",
} as const;

const statusStyles = {
  new: "border-accent/30 bg-accent/10 text-accent",
  triaged: "border-warning/30 bg-warning/10 text-warning",
  escalated: "border-danger/30 bg-danger/10 text-danger",
  closed: "border-white/20 bg-white/5 text-muted",
} as const;

export function CaseCard({
  item,
  onOpen,
}: {
  item: RiskCase;
  onOpen?: (item: RiskCase) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onOpen?.(item)}
      className={cn(
        "w-full rounded-xl border border-white/8 border-l-4 bg-surface p-4 text-left transition-all hover:border-white/15 hover:bg-white/[0.02]",
        severityBorder[item.severity as keyof typeof severityBorder] ?? severityBorder.medium,
      )}
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="mb-1 font-data text-[10px] uppercase tracking-[0.24em] text-muted">
            #{item.id} · {new Date(item.created_at).toLocaleString()}
          </div>
          <div className="font-heading text-base font-semibold text-white">{item.title}</div>
        </div>
        <div
          className={cn(
            "rounded-full border px-2.5 py-1 font-data text-[10px] uppercase tracking-[0.18em]",
            statusStyles[item.status as keyof typeof statusStyles] ?? statusStyles.new,
          )}
        >
          {item.status}
        </div>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <span className="rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 font-data text-[10px] uppercase tracking-[0.18em] text-slate-300">
          {item.severity}
        </span>
        {item.tags?.map((tag) => (
          <span
            key={tag}
            className="rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 font-data text-[10px] text-muted"
          >
            {tag}
          </span>
        ))}
        {item.risk_score !== null ? (
          <span className="font-data text-xs text-slate-300">Score {item.risk_score}</span>
        ) : null}
      </div>
    </button>
  );
}
