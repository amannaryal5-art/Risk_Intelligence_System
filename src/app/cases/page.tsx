"use client";

import { useEffect, useState } from "react";

import { CaseCard } from "@/components/cases/CaseCard";
import { CaseModal } from "@/components/cases/CaseModal";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { useCases } from "@/hooks/useCases";
import type { RiskCase } from "@/types/cases";

export default function CasesPage() {
  const [apiKey, setApiKey] = useState("");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [selectedCase, setSelectedCase] = useState<RiskCase | null>(null);
  const { cases, refresh, isLoading, error } = useCases(apiKey, 50);

  useEffect(() => {
    setApiKey(window.localStorage.getItem("riskintel_api_key")?.trim() ?? "");
  }, []);

  const filtered = cases.filter((item) => (!status || item.status === status) && (!severity || item.severity === severity));

  const createCase = async () => {
    await api.cases.create(
      {
        title: "Manual analyst case",
        severity: "medium",
        status: "new",
        source_type: "manual",
        findings: { created_from: "Next.js case page" },
      },
      apiKey,
    );
    refresh().catch(() => null);
  };

  return (
    <main className="min-h-screen bg-bg px-4 py-6 text-white lg:px-8">
      <div className="mx-auto max-w-6xl space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="font-data text-xs uppercase tracking-[0.28em] text-accent">Case Management</div>
            <div className="mt-2 font-heading text-4xl uppercase tracking-[0.08em] text-white">
              Track triage, escalation, and closure
            </div>
          </div>
          <Button onClick={createCase}>Create Manual Case</Button>
        </div>

        <section className="rounded-[2rem] border border-white/8 bg-black/20 p-5">
          <div className="grid gap-4 lg:grid-cols-3">
            <select
              value={status}
              onChange={(event) => setStatus(event.target.value)}
              className="rounded-xl border border-white/10 bg-[#060b12] px-3 py-3 font-data text-sm text-slate-100 outline-none"
            >
              <option value="">All statuses</option>
              <option value="new">new</option>
              <option value="triaged">triaged</option>
              <option value="escalated">escalated</option>
              <option value="closed">closed</option>
            </select>
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
              className="rounded-xl border border-white/10 bg-[#060b12] px-3 py-3 font-data text-sm text-slate-100 outline-none"
            >
              <option value="">All severities</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
            <Button variant="outline" onClick={() => refresh()}>
              Refresh
            </Button>
          </div>
        </section>

        {isLoading ? <div className="font-data text-sm text-muted">Loading cases...</div> : null}
        {error ? <div className="font-data text-sm text-danger">{error}</div> : null}

        <section className="grid gap-4">
          {filtered.map((item) => (
            <CaseCard key={item.id} item={item} onOpen={setSelectedCase} />
          ))}
        </section>
      </div>

      <CaseModal item={selectedCase} onClose={() => setSelectedCase(null)} />
    </main>
  );
}
