import { labelForInputType } from "@/lib/detectInputType";
import { cn } from "@/lib/utils";
import type { InputType } from "@/types/analysis";

const toneMap: Record<InputType, string> = {
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

export function TypeBadge({ type }: { type: InputType }) {
  return (
    <span
      className={cn(
        "rounded-full border px-3 py-1 font-data text-[10px] uppercase tracking-[0.2em]",
        toneMap[type],
      )}
    >
      {labelForInputType(type)}
    </span>
  );
}
