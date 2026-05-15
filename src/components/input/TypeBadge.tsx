import { labelForInputType } from "@/lib/detectInputType";
import type { InputType } from "@/types/analysis";

export function TypeBadge({ type }: { type: InputType }) {
  return (
    <span className="rounded-full border border-accent/20 bg-accent/10 px-3 py-1 font-data text-[11px] uppercase tracking-[0.18em] text-accent">
      {labelForInputType(type)}
    </span>
  );
}
