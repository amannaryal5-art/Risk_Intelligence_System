import { cn } from "@/lib/utils";

const badgeStyles = {
  neutral: "border-white/10 bg-white/5 text-slate-200",
  blue: "border-blue-500/30 bg-blue-500/10 text-blue-300",
  green: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  red: "border-red-500/30 bg-red-500/10 text-red-300",
  yellow: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  purple: "border-violet-500/30 bg-violet-500/10 text-violet-300",
} as const;

export function Badge({
  children,
  tone = "neutral",
  className,
}: {
  children: React.ReactNode;
  tone?: keyof typeof badgeStyles;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.24em]",
        badgeStyles[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}
