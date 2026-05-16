"use client";

import { useEffect, useState } from "react";

import { AddAssetForm } from "@/components/assets/AddAssetForm";
import { AssetList } from "@/components/assets/AssetList";
import { Badge } from "@/components/shared/Badge";
import { useAssets } from "@/hooks/useAssets";
import type { AssetHistoryEntry } from "@/lib/types";

function parseJsonList(value?: string) {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export default function AssetsPage() {
  const { selectedAsset, fetchAssetHistory, fetchAssetSummary } = useAssets();
  const [history, setHistory] = useState<AssetHistoryEntry[]>([]);
  const [summary, setSummary] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!selectedAsset) {
      setHistory([]);
      setSummary("");
      return;
    }

    setLoading(true);
    Promise.all([fetchAssetHistory(selectedAsset.id), fetchAssetSummary(selectedAsset.id)])
      .then(([nextHistory, nextSummary]) => {
        setHistory(nextHistory);
        setSummary(nextSummary.summary);
      })
      .finally(() => setLoading(false));
  }, [fetchAssetHistory, fetchAssetSummary, selectedAsset]);

  const latest = history[0];
  const findings = parseJsonList(latest?.key_findings);
  const indicators = parseJsonList(latest?.threat_indicators);

  return (
    <div className="grid gap-6 xl:grid-cols-[320px_minmax(0,1fr)]">
      <div className="space-y-4">
        <AddAssetForm />
        <AssetList />
      </div>

      <section className="panel min-h-[640px] p-5">
        {selectedAsset ? (
          <div className="space-y-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="eyebrow">{selectedAsset.type.toUpperCase()}</div>
                <h1 className="mt-2 text-2xl font-semibold text-white">{selectedAsset.name || selectedAsset.value}</h1>
                <div className="mt-2 font-mono text-sm text-slate-500">{selectedAsset.value}</div>
              </div>
              <Badge tone="blue">{selectedAsset.last_risk_level ?? "Unknown"}</Badge>
            </div>

            {loading ? (
              <div className="text-sm text-slate-400">Loading threat data...</div>
            ) : (
              <>
                <section className="rounded-lg border border-white/10 bg-white/5 p-4">
                  <div className="eyebrow">AI Summary</div>
                  <p className="mt-3 text-sm leading-7 text-slate-200">
                    {summary || "No summary available for this asset yet."}
                  </p>
                </section>

                {findings.length ? (
                  <section className="rounded-lg border border-white/10 bg-white/5 p-4">
                    <div className="eyebrow">Key Findings</div>
                    <div className="mt-3 space-y-2 text-sm text-slate-200">
                      {findings.map((finding: string) => (
                        <div key={finding}>{finding}</div>
                      ))}
                    </div>
                  </section>
                ) : null}

                {indicators.length ? (
                  <section className="rounded-lg border border-white/10 bg-white/5 p-4">
                    <div className="eyebrow">Threat Indicators</div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {indicators.map((indicator: string) => (
                        <Badge key={indicator} tone="red">
                          {indicator}
                        </Badge>
                      ))}
                    </div>
                  </section>
                ) : null}

                <section className="rounded-lg border border-white/10 bg-white/5 p-4">
                  <div className="eyebrow">Scan History</div>
                  <div className="mt-4 overflow-hidden rounded-lg border border-white/10">
                    <table className="min-w-full divide-y divide-white/10 text-left text-sm">
                      <thead className="bg-black/20 text-slate-400">
                        <tr>
                          <th className="px-4 py-3 font-medium">Risk</th>
                          <th className="px-4 py-3 font-medium">Score</th>
                          <th className="px-4 py-3 font-medium">When</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/10">
                        {history.length ? (
                          history.map((entry) => (
                            <tr key={entry.id}>
                              <td className="px-4 py-3 text-white">{entry.risk_level ?? "Unknown"}</td>
                              <td className="px-4 py-3 font-mono text-slate-300">{entry.risk_score ?? "--"}</td>
                              <td className="px-4 py-3 font-mono text-slate-500">{entry.scanned_at ?? "--"}</td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td className="px-4 py-4 text-slate-400" colSpan={3}>
                              No scan history available yet.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </section>
              </>
            )}
          </div>
        ) : (
          <div className="flex h-full min-h-[500px] items-center justify-center text-center">
            <div>
              <div className="eyebrow">Asset Detail</div>
              <h1 className="mt-3 text-2xl font-semibold text-white">Select an asset to view threat data</h1>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
