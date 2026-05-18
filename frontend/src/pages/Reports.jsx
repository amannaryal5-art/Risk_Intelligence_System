import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Download } from 'lucide-react'
import client from '../api/client'
import Spinner from '../components/ui/Spinner'
import EmptyPanel from '../components/shared/EmptyPanel'
import { downloadJson, formatDate } from '../lib/utils'

export default function Reports() {
  const queryClient = useQueryClient()
  const [selectedId, setSelectedId] = useState(null)

  const reportsQuery = useQuery({
    queryKey: ['reports'],
    queryFn: async () => (await client.get('/api/reports')).data,
  })

  const reportQuery = useQuery({
    queryKey: ['report', selectedId],
    queryFn: async () => (await client.get(`/api/reports/${selectedId}`)).data,
    enabled: !!selectedId,
  })

  const generateMutation = useMutation({
    mutationFn: async () => (await client.post('/api/reports/generate')).data,
    onSuccess: (data) => {
      toast.success('Report generated')
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      if (data?.id) setSelectedId(data.id)
    },
    onError: (err) => toast.error(err.response?.data?.detail || 'Report generation failed'),
  })

  const reports = reportsQuery.data || []
  const report = reportQuery.data

  return (
    <div className="grid gap-6 xl:grid-cols-[0.8fr_1.2fr]">
      <div className="space-y-4">
        <div className="flex justify-end">
          <button type="button" className="btn-primary" disabled={generateMutation.isPending} onClick={() => generateMutation.mutate()}>
            {generateMutation.isPending ? <Spinner /> : null}
            Generate report
          </button>
        </div>

        {reportsQuery.isLoading ? (
          <div className="panel flex min-h-[120px] items-center justify-center"><Spinner /></div>
        ) : reports.length === 0 ? (
          <EmptyPanel icon="Reports" title="No reports yet" subtitle='Click "Generate report" to create your first intelligence briefing.' />
        ) : (
          reports.map((item) => (
            <button key={item.id} type="button" className={`panel w-full p-5 text-left transition ${selectedId === item.id ? 'ring-1 ring-blue-500/50' : ''}`} onClick={() => setSelectedId(item.id)}>
              <p className="font-mono text-sm text-slate-50">{item.title}</p>
              <p className="mt-2 text-xs text-slate-500">{formatDate(item.generated_at)}</p>
            </button>
          ))
        )}
      </div>

      <div className="panel-elevated min-h-[600px] p-6">
        {reportQuery.isLoading ? (
          <div className="flex h-full items-center justify-center"><Spinner /></div>
        ) : report ? (
          <>
            <div className="mb-6 flex items-start justify-between gap-4">
              <div>
                <h2 className="font-mono text-2xl text-slate-50">{report.title}</h2>
                <p className="mt-2 text-sm text-slate-500">{formatDate(report.generated_at)}</p>
              </div>
              <button type="button" className="btn-secondary shrink-0" onClick={() => downloadJson(`report-${report.id}.json`, report)}>
                <Download className="h-4 w-4" />
                Export
              </button>
            </div>
            <div className="space-y-5 text-sm text-slate-300">
              <section>
                <p className="section-title">Executive Summary</p>
                <p className="mt-3">Assets: {report.content?.summary?.asset_count || 0} | Avg Risk: {report.content?.summary?.avg_risk_score || 0}</p>
                <p className="mt-2">Highest risk asset: {report.content?.summary?.highest_risk_asset || 'n/a'} ({report.content?.summary?.highest_risk_score || 0})</p>
              </section>
              <section>
                <p className="section-title">Top Risk Assets</p>
                <div className="mt-3 space-y-2">
                  {(report.content?.top_assets || []).map((asset) => (
                    <div key={asset.id} className="rounded-xl border border-border bg-slate-950/50 px-4 py-3">
                      {asset.label} - score {asset.risk_score ?? 0} ({asset.risk_level})
                    </div>
                  ))}
                </div>
              </section>
              <section>
                <p className="section-title">Feed Health</p>
                <div className="mt-3 grid gap-2">
                  {(report.content?.feed_health || []).map((feed) => (
                    <div key={feed.name} className="rounded-xl border border-border bg-slate-950/50 px-4 py-3">
                      {feed.display_name}: {feed.auth_valid ? 'OK' : feed.warning || 'degraded'}
                    </div>
                  ))}
                </div>
              </section>
              {report.content?.device_posture?.available ? (
                <section>
                  <p className="section-title">Device Posture</p>
                  <div className="mt-3 space-y-2 rounded-xl border border-border bg-slate-950/50 px-4 py-3 text-sm">
                    <p>
                      Device Risk Score: {report.content.device_posture.device_risk_score}/100
                      {report.content.device_posture.delta != null
                        ? ` (${report.content.device_posture.delta >= 0 ? '↑' : '↓'} from ${report.content.device_posture.previous_risk_score} yesterday)`
                        : ''}
                    </p>
                    <p>
                      Network: {report.content.device_posture.connections_total} total, {report.content.device_posture.connections_flagged} flagged
                    </p>
                    <p>
                      Processes: {report.content.device_posture.processes_total} total, {report.content.device_posture.processes_flagged} suspicious
                    </p>
                    <p>
                      Open Ports: {report.content.device_posture.ports_open} listening ({report.content.device_posture.ports_suspicious} exposed)
                    </p>
                    <p>
                      Startup: {report.content.device_posture.startup_items} total, {report.content.device_posture.startup_flagged} unusual
                    </p>
                    <p className="font-medium text-slate-100">Verdict: {report.content.device_posture.verdict}</p>
                  </div>
                </section>
              ) : null}
              {report.content?.unified_intelligence_summary?.latest ? (
                <section>
                  <p className="section-title">Unified Intelligence Summary</p>
                  <div className="mt-3 rounded-xl border border-border bg-slate-950/50 px-4 py-3">
                    Latest overall risk: {report.content.unified_intelligence_summary.latest.overall_risk_score || 0}
                    {report.content.unified_intelligence_summary.delta != null ? ` | Delta: ${report.content.unified_intelligence_summary.delta}` : ''}
                  </div>
                  <div className="mt-3 space-y-2">
                    {(report.content.unified_intelligence_summary.top_threats || []).map((item, index) => (
                      <div key={index} className="rounded-xl border border-border bg-slate-950/50 px-4 py-3">
                        {item.asset?.label || item.target} - {item.verdict} ({item.risk_score})
                      </div>
                    ))}
                  </div>
                </section>
              ) : null}
              <section>
                <p className="section-title">Recommendations</p>
                <div className="mt-3 space-y-2">
                  {(report.content?.recommendations || []).map((item, index) => (
                    <div key={index} className="rounded-xl border border-border bg-slate-950/50 px-4 py-3">{item}</div>
                  ))}
                </div>
              </section>
            </div>
          </>
        ) : (
          <div className="flex h-full items-center justify-center">
            <p className="text-sm text-slate-500">Select a report from the list to view it.</p>
          </div>
        )}
      </div>
    </div>
  )
}
