import type { AssetAlert } from "@/lib/types";

function bucketAlerts(alerts: AssetAlert[]) {
  const buckets = Array.from({ length: 6 }, (_, index) => {
    const start = new Date();
    start.setHours(start.getHours() - (5 - index) * 4);
    return {
      label: `${start.getHours().toString().padStart(2, "0")}:00`,
      count: 0,
    };
  });

  alerts.forEach((alert) => {
    const hourDelta = (Date.now() - new Date(alert.created_at).getTime()) / (1000 * 60 * 60);
    const bucketIndex = 5 - Math.min(5, Math.floor(hourDelta / 4));
    if (bucketIndex >= 0 && bucketIndex < buckets.length) {
      buckets[bucketIndex].count += 1;
    }
  });

  return buckets;
}

export function ThreatLandscape({ alerts }: { alerts: AssetAlert[] }) {
  const buckets = bucketAlerts(alerts);
  const max = Math.max(...buckets.map((bucket) => bucket.count), 1);

  return (
    <section className="panel panel-grid flex h-full min-h-[360px] flex-col p-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="eyebrow">Threat Landscape</div>
          <h2 className="mt-2 text-xl font-semibold text-white">Live threat timeline</h2>
        </div>
        <button className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 transition hover:border-white/20 hover:text-white">
          Pause Timeline
        </button>
      </div>

      <div className="mt-8 flex flex-1 items-end gap-4">
        {buckets.map((bucket) => (
          <div key={bucket.label} className="flex flex-1 flex-col items-center gap-3">
            <div className="flex h-56 w-full items-end rounded-lg border border-white/10 bg-black/20 p-2">
              <div
                className="w-full rounded-md bg-gradient-to-t from-blue-500 via-violet-500 to-red-500 transition-all duration-500"
                style={{ height: `${Math.max(8, (bucket.count / max) * 100)}%` }}
              />
            </div>
            <div className="text-center">
              <div className="font-mono text-xs text-slate-500">{bucket.label}</div>
              <div className="mt-1 text-sm text-white">{bucket.count}</div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
