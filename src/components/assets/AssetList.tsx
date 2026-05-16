"use client";

import { RefreshCcw, Trash2 } from "lucide-react";

import { Badge } from "@/components/shared/Badge";
import { useAssets } from "@/hooks/useAssets";
import type { Asset } from "@/lib/types";

function riskTone(asset: Asset) {
  const level = asset.last_risk_level ?? "Unknown";
  if (level === "Critical") return "red";
  if (level === "High") return "yellow";
  if (level === "Clean" || level === "Low") return "green";
  return "blue";
}

export function AssetList() {
  const { assets, deleteAsset, scanAsset, selectedAssetId, selectAsset } = useAssets();

  return (
    <section className="panel flex min-h-[320px] flex-col p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="eyebrow">Monitored Assets</div>
        <Badge tone="blue">{assets.length}</Badge>
      </div>

      <div className="mt-4 flex-1 space-y-2 overflow-y-auto">
        {assets.length ? (
          assets.map((asset) => (
            <div
              key={asset.id}
              className={`w-full rounded-lg border p-3 text-left transition ${
                selectedAssetId === asset.id
                  ? "border-blue-500/30 bg-blue-500/10"
                  : "border-white/10 bg-white/5 hover:border-white/20 hover:bg-white/[0.07]"
              }`}
              onClick={() => selectAsset(asset.id)}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-white">{asset.name || asset.value}</div>
                  <div className="mt-1 truncate font-mono text-xs text-slate-500">{asset.value}</div>
                  <div className="mt-2">
                    <Badge tone={riskTone(asset)}>{asset.last_risk_level ?? "Unknown"}</Badge>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    className="rounded-md p-2 text-slate-400 transition hover:bg-white/5 hover:text-white"
                    onClick={(event) => {
                      event.stopPropagation();
                      scanAsset(asset.id).catch(() => null);
                    }}
                  >
                    <RefreshCcw className="h-4 w-4" />
                  </button>
                  <button
                    type="button"
                    className="rounded-md p-2 text-slate-400 transition hover:bg-white/5 hover:text-red-300"
                    onClick={(event) => {
                      event.stopPropagation();
                      deleteAsset(asset.id).catch(() => null);
                    }}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="rounded-lg border border-dashed border-white/10 p-4 text-sm text-slate-400">
            No assets yet. Add one above to begin monitoring.
          </div>
        )}
      </div>
    </section>
  );
}
