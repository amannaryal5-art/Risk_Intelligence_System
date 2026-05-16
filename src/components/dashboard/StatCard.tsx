import { Badge } from "@/components/shared/Badge";
import type { DashboardMetric } from "@/lib/types";

const toneMap = {
  blue: "blue",
  green: "green",
  red: "red",
  yellow: "yellow",
  purple: "purple",
} as const;

export function StatCard({ metric }: { metric: DashboardMetric }) {
  return (
    <section className="panel panel-grid p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="eyebrow">{metric.title}</div>
          <div className="mt-3 text-3xl font-semibold text-white">{metric.value}</div>
        </div>
        {metric.trend ? <Badge tone={toneMap[metric.tone ?? "blue"]}>{metric.trend}</Badge> : null}
      </div>
      <div className="mt-4 text-sm text-slate-300">{metric.subtext}</div>
      <div className="mt-3 font-mono text-xs text-slate-500">{metric.footer}</div>
    </section>
  );
}
