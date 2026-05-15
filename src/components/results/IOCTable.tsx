import type { ThreatIntelResponse } from "@/types/analysis";

export function IOCTable({ threatIntel }: { threatIntel: ThreatIntelResponse | null | undefined }) {
  const rows = threatIntel?.results ?? [];

  return (
    <div className="overflow-hidden rounded-2xl border border-white/8">
      <table className="w-full border-collapse font-data text-sm">
        <thead className="bg-white/[0.03] text-left text-xs uppercase tracking-[0.18em] text-muted">
          <tr>
            <th className="px-4 py-3">IOC</th>
            <th className="px-4 py-3">Type</th>
            <th className="px-4 py-3">Risk</th>
            <th className="px-4 py-3">OTX</th>
            <th className="px-4 py-3">AbuseIPDB</th>
            <th className="px-4 py-3">VirusTotal</th>
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows.slice(0, 10).map((row) => {
              const otx = row.feeds.find((feed) => feed.source === "otx");
              const abuse = row.feeds.find((feed) => feed.source === "abuseipdb");
              const vt = row.feeds.find((feed) => feed.source === "virustotal");
              return (
                <tr key={`${row.ioc_type}-${row.value}`} className="border-t border-white/6 text-slate-200">
                  <td className="px-4 py-3">{row.value}</td>
                  <td className="px-4 py-3 uppercase">{row.ioc_type}</td>
                  <td className="px-4 py-3">{row.reputation_score}</td>
                  <td className="px-4 py-3">{otx?.pulse_count ?? 0}</td>
                  <td className="px-4 py-3">{abuse?.abuse_confidence ?? 0}</td>
                  <td className="px-4 py-3">{vt?.malicious_votes ?? 0}</td>
                </tr>
              );
            })
          ) : (
            <tr>
              <td colSpan={6} className="px-4 py-5 text-center text-muted">
                No IOC intelligence returned.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
