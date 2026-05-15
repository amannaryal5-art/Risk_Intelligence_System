import type { WebsiteIntelResponse } from "@/types/analysis";

export function WebsitePanel({ websiteIntel }: { websiteIntel: WebsiteIntelResponse | null | undefined }) {
  if (!websiteIntel) {
    return (
      <div className="rounded-xl border border-white/8 bg-black/20 p-4 font-data text-sm text-muted">
        Website intelligence is only shown for URL and domain-driven scans.
      </div>
    );
  }

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="rounded-xl border border-white/8 bg-black/20 p-4">
        <div className="font-data text-xs uppercase tracking-[0.18em] text-muted">Domain</div>
        <div className="mt-2 font-heading text-2xl text-white">{websiteIntel.domain}</div>
      </div>
      <div className="rounded-xl border border-white/8 bg-black/20 p-4">
        <div className="font-data text-xs uppercase tracking-[0.18em] text-muted">Resolved IP</div>
        <div className="mt-2 font-heading text-2xl text-white">{websiteIntel.ip || "Unavailable"}</div>
      </div>
      <div className="rounded-xl border border-white/8 bg-black/20 p-4">
        <div className="font-data text-xs uppercase tracking-[0.18em] text-muted">Threat Verdict</div>
        <div className="mt-2 font-heading text-2xl text-white">{websiteIntel.verdict}</div>
      </div>
    </div>
  );
}
