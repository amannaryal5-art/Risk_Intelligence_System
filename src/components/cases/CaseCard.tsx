import type { RiskCase } from "@/types/cases";

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
      className="w-full rounded-2xl border border-white/8 bg-black/20 p-4 text-left transition hover:border-accent/20 hover:bg-black/30"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="font-heading text-xl uppercase tracking-[0.06em] text-white">{item.title}</div>
        <div className="font-data text-xs uppercase tracking-[0.18em] text-accent">{item.status}</div>
      </div>
      <div className="mt-3 font-data text-sm text-slate-300">
        Severity {item.severity} {item.risk_score !== null ? `| Score ${item.risk_score}` : ""}
      </div>
    </button>
  );
}
