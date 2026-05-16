import type { Asset, AssetAlert } from "@/lib/types";

export function ProcessingPipeline({
  assets,
  alerts,
  queuedActions,
}: {
  assets: Asset[];
  alerts: AssetAlert[];
  queuedActions: number;
}) {
  const stages = [
    { label: "Collection", value: assets.length, detail: "Asset telemetry intake" },
    { label: "Enrichment", value: Math.max(alerts.length, assets.length), detail: "VirusTotal + AbuseIPDB + OTX" },
    { label: "Scoring", value: assets.filter((asset) => asset.last_risk_score).length, detail: "Risk scoring and summarization" },
    { label: "Queue", value: queuedActions, detail: "Queued analyst actions while offline" },
    { label: "Response", value: alerts.length, detail: "Autonomous alert publication" },
  ];

  return (
    <section className="panel p-5">
      <div className="eyebrow">Processing Pipeline</div>
      <h2 className="mt-2 text-xl font-semibold text-white">Worker stages and flow state</h2>

      <div className="mt-6 space-y-4">
        {stages.map((stage, index) => (
          <div key={stage.label} className="flex items-center gap-4">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-blue-500/20 bg-blue-500/10 text-sm font-semibold text-blue-300">
              {index + 1}
            </div>
            <div className="min-w-0 flex-1 rounded-lg border border-white/10 bg-white/5 p-4">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-sm font-medium text-white">{stage.label}</div>
                  <div className="mt-1 text-sm text-slate-400">{stage.detail}</div>
                </div>
                <div className="text-2xl font-semibold text-white">{stage.value}</div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
