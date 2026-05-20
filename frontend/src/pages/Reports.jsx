import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Download } from 'lucide-react'
import client from '../api/client'
import Spinner from '../components/ui/Spinner'
import EmptyPanel from '../components/shared/EmptyPanel'
import { downloadJson, formatDate } from '../lib/utils'

function buildReportText(report) {
  if (!report) return ''
  if (typeof report.content === 'string') return report.content
  const content = report.content || {}
  const lines = [
    '== DAILY THREAT INTELLIGENCE BRIEFING ==',
    `TITLE: ${report.title || 'Untitled report'}`,
    `GENERATED: ${formatDate(report.generated_at)}`,
    '',
    '== EXECUTIVE SUMMARY ==',
    `ASSETS: ${content.summary?.asset_count || 0}`,
    `AVG_RISK: ${content.summary?.avg_risk_score || 0}`,
    `HIGHEST_RISK_ASSET: ${content.summary?.highest_risk_asset || 'n/a'} (${content.summary?.highest_risk_score || 0})`,
    '',
    '== TOP RISK ASSETS ==',
    ...((content.top_assets || []).map((asset) => `${asset.label}: score ${asset.risk_score ?? 0} :: ${String(asset.risk_level || 'unknown').toUpperCase()}`)),
    '',
    '== FEED HEALTH ==',
    ...((content.feed_health || []).map((feed) => `${feed.display_name}: ${feed.auth_valid ? 'SUCCESS' : feed.warning || 'WARNING'}`)),
  ]

  if (content.device_posture?.available) {
    lines.push(
      '',
      '== DEVICE POSTURE ==',
      `DEVICE_RISK_SCORE: ${content.device_posture.device_risk_score}/100`,
      `NETWORK: ${content.device_posture.connections_total} total :: ${content.device_posture.connections_flagged} flagged`,
      `PROCESSES: ${content.device_posture.processes_total} total :: ${content.device_posture.processes_flagged} suspicious`,
      `OPEN_PORTS: ${content.device_posture.ports_open} listening :: ${content.device_posture.ports_suspicious} suspicious`,
      `STARTUP: ${content.device_posture.startup_items} total :: ${content.device_posture.startup_flagged} unusual`,
      `VERDICT: ${content.device_posture.verdict}`,
    )
  }

  if (content.unified_intelligence_summary?.latest) {
    lines.push(
      '',
      '== UNIFIED INTELLIGENCE ==',
      `OVERALL_RISK: ${content.unified_intelligence_summary.latest.overall_risk_score || 0}`,
      ...((content.unified_intelligence_summary.top_threats || []).map((item) => `${item.asset?.label || item.target}: ${item.verdict} (${item.risk_score})`)),
    )
  }

  lines.push('', '== RECOMMENDATIONS ==', ...((content.recommendations || []).map((item) => `- ${item}`)))
  return lines.join('\n')
}

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
  const reportText = useMemo(() => buildReportText(report), [report])

  useEffect(() => {
    if (!selectedId && reports.length) {
      setSelectedId(reports[0].id)
    }
  }, [reports, selectedId])

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
            <button
              key={item.id}
              type="button"
              className={`panel w-full p-5 text-left transition ${selectedId === item.id ? 'ring-1 ring-cyber-cyan/50 bg-cyber-cyan/5' : ''}`}
              onClick={() => setSelectedId(item.id)}
            >
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
            <div className="h-[32rem] overflow-auto rounded-xl border border-cyber-cyan/20 bg-black p-5 font-mono text-[11px] leading-7">
              {reportText.split('\n').map((line, index) => (
                <div
                  key={`${report.id}-${index}`}
                  className={
                    line.startsWith('==')
                      ? 'text-cyan-300'
                      : /CRITICAL|COMPROMISED|ERROR|\[!\]/.test(line)
                        ? 'text-red-400'
                        : /SECURE|SUCCESS|LIVE|CLEAN/.test(line)
                          ? 'text-emerald-400'
                          : /MEDIUM|WARNING|AT RISK|HIGH RISK|LOW RISK/.test(line)
                            ? 'text-orange-300'
                            : 'text-slate-200'
                  }
                >
                  {line || '\u00A0'}
                </div>
              ))}
            </div>
          </>
        ) : (
          <div className="flex h-full items-center justify-center font-mono text-sm text-slate-500">
            <div className="text-center">
              <div>root@crie:~$ cat report.log</div>
              <div>cat: No report selected</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
