import type { FeedProviderStatus } from "@/lib/types";

function statusLabel(feed: FeedProviderStatus) {
  if (!feed.configured) return "Not configured";
  if (feed.reachable && feed.auth_valid !== false) return "Operational";
  return "Degraded";
}

export function FeedHealth({ feeds }: { feeds: FeedProviderStatus[] }) {
  return (
    <div className="space-y-3">
      {feeds.length ? (
        feeds.map((feed) => (
          <div key={feed.name} className="rounded-lg border border-white/10 bg-white/5 p-3">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-medium text-white">{feed.name}</div>
                <div className="mt-1 font-mono text-xs text-slate-500">
                  {feed.latency_ms ? `${feed.latency_ms}ms` : "No latency signal"}
                </div>
              </div>
              <span
                className={`rounded-full px-2 py-1 font-mono text-[10px] uppercase tracking-[0.22em] ${
                  feed.reachable && feed.auth_valid !== false
                    ? "bg-emerald-500/10 text-emerald-300"
                    : "bg-amber-500/10 text-amber-300"
                }`}
              >
                {statusLabel(feed)}
              </span>
            </div>
          </div>
        ))
      ) : (
        <div className="rounded-lg border border-dashed border-white/10 p-4 text-sm text-slate-400">
          Provider telemetry will appear here once feed status data is available.
        </div>
      )}
    </div>
  );
}
