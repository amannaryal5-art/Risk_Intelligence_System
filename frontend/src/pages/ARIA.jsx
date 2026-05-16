import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import ReactMarkdown from 'react-markdown'
import { Bot, Send, Shield } from 'lucide-react'
import { addAriaAsset, ariaChat, deleteAriaAsset, generateAriaReport, getAriaAlerts, getAriaAssetHistory, getAriaAssetSummary, getAriaAssets, getAriaStats, markAllAriaAlertsSeen, markAriaAlertSeen, scanAriaAsset } from '../api/aria'
import RiskBadge from '../components/ui/RiskBadge'
import Spinner from '../components/ui/Spinner'
import { formatDate } from '../lib/utils'
import { useAuthStore } from '../store/authStore'

export default function ARIA() {
  const queryClient = useQueryClient()
  const user = useAuthStore((state) => state.user)
  const canEdit = user?.role !== 'viewer'
  const [draft, setDraft] = useState({ name: '', type: 'domain', value: '', scan_interval_hours: 6 })
  const [messages, setMessages] = useState([{ role: 'assistant', content: 'ARIA online. Ask for asset posture, risk summaries, or threat triage support.' }])
  const [prompt, setPrompt] = useState('')
  const [summaryMap, setSummaryMap] = useState({})

  const assetsQuery = useQuery({ queryKey: ['aria', 'assets'], queryFn: getAriaAssets })
  const alertsQuery = useQuery({ queryKey: ['aria', 'alerts'], queryFn: getAriaAlerts })
  const statsQuery = useQuery({ queryKey: ['aria', 'stats'], queryFn: getAriaStats })

  const addAssetMutation = useMutation({
    mutationFn: () => addAriaAsset({ ...draft, scan_interval_hours: Number(draft.scan_interval_hours) }),
    onSuccess: () => {
      setDraft({ name: '', type: 'domain', value: '', scan_interval_hours: 6 })
      queryClient.invalidateQueries({ queryKey: ['aria'] })
      toast.success('Asset added')
    },
  })
  const chatMutation = useMutation({
    mutationFn: () => ariaChat({ messages: [...messages, { role: 'user', content: prompt }] }),
    onSuccess: (data) => {
      setMessages((current) => [...current, { role: 'user', content: prompt }, { role: 'assistant', content: data.reply }])
      setPrompt('')
    },
  })
  const generateReportMutation = useMutation({
    mutationFn: generateAriaReport,
    onSuccess: () => toast.success('Daily report generation triggered'),
  })

  const assetStats = useMemo(() => ({
    critical: (assetsQuery.data || []).filter((item) => item.last_risk_level === 'Critical').length,
    high: (assetsQuery.data || []).filter((item) => item.last_risk_level === 'High').length,
    medium: (assetsQuery.data || []).filter((item) => item.last_risk_level === 'Medium').length,
    low: (assetsQuery.data || []).filter((item) => item.last_risk_level === 'Low').length,
    clean: (assetsQuery.data || []).filter((item) => item.last_risk_level === 'Clean').length,
  }), [assetsQuery.data])

  return (
    <div className="space-y-6">
      <div className="grid gap-6 xl:grid-cols-[0.85fr_1.15fr]">
        <div className="panel p-5">
          <div className="flex items-center justify-between">
            <p className="section-title">Asset Monitor</p>
            <button type="button" className="btn-primary" disabled={!canEdit || addAssetMutation.isPending} onClick={() => addAssetMutation.mutate()}>Add Asset</button>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <input className="field" placeholder="Name" value={draft.name} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} />
            <select className="field" value={draft.type} onChange={(event) => setDraft((current) => ({ ...current, type: event.target.value }))}><option>domain</option><option>ip</option><option>url</option><option>email</option></select>
            <input className="field md:col-span-2" placeholder="Value" value={draft.value} onChange={(event) => setDraft((current) => ({ ...current, value: event.target.value }))} />
            <input className="field md:col-span-2" type="number" min="1" value={draft.scan_interval_hours} onChange={(event) => setDraft((current) => ({ ...current, scan_interval_hours: event.target.value }))} />
          </div>
          <div className="mt-4 grid grid-cols-5 gap-2 text-center text-xs">
            {Object.entries(assetStats).map(([key, value]) => <div key={key} className="rounded-xl border border-border bg-slate-950/50 p-3"><p className="font-mono text-base">{value}</p><p className="mt-1 uppercase text-slate-500">{key}</p></div>)}
          </div>
          <div className="mt-4 space-y-3">
            {(assetsQuery.data || []).map((asset) => (
              <div key={asset.id} className="rounded-xl border border-border bg-slate-950/50 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium text-slate-100">{asset.name || asset.value}</p>
                    <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{asset.type} • {asset.value}</p>
                  </div>
                  <RiskBadge level={asset.last_risk_level || 'unknown'} />
                </div>
                <p className="mt-3 text-sm text-slate-400">{summaryMap[asset.id] || asset.last_summary || 'No summary yet.'}</p>
                <p className="mt-2 text-xs text-slate-500">Last scanned: {formatDate(asset.last_scanned_at || asset.last_scanned)}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button type="button" className="btn-secondary px-3 py-2" disabled={!canEdit} onClick={() => scanAriaAsset(asset.id).then(() => toast.success('Asset scan triggered'))}>Scan Now</button>
                  <button type="button" className="btn-secondary px-3 py-2" onClick={() => queryClient.prefetchQuery({ queryKey: ['aria', 'history', asset.id], queryFn: () => getAriaAssetHistory(asset.id) })}>History</button>
                  <button type="button" className="btn-secondary px-3 py-2" onClick={async () => {
                    const result = await getAriaAssetSummary(asset.id)
                    setSummaryMap((current) => ({ ...current, [asset.id]: result.summary }))
                  }}>Summary</button>
                  <button type="button" className="btn-danger px-3 py-2" disabled={!canEdit} onClick={() => deleteAriaAsset(asset.id).then(() => queryClient.invalidateQueries({ queryKey: ['aria'] }))}>Delete</button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="panel-elevated flex min-h-[700px] flex-col p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="section-title">AI Analyst Chat</p>
              <p className="mt-2 text-sm text-slate-400">Monitoring {statsQuery.data?.total || 0} assets, {statsQuery.data?.unseen_alerts || 0} unseen alerts</p>
            </div>
            <button type="button" className="btn-primary" disabled={generateReportMutation.isPending} onClick={() => generateReportMutation.mutate()}>
              Generate Daily Report
            </button>
          </div>

          <div className="mt-5 flex-1 space-y-4 overflow-auto rounded-2xl border border-border bg-slate-950/50 p-4">
            {messages.map((message, index) => (
              <div key={index} className={`flex gap-3 ${message.role === 'assistant' ? '' : 'justify-end'}`}>
                {message.role === 'assistant' ? <div className="mt-1 rounded-xl bg-purple-600/20 p-2"><Bot className="h-4 w-4 text-purple-300" /></div> : null}
                <div className={`max-w-[80%] rounded-2xl border px-4 py-3 text-sm ${message.role === 'assistant' ? 'border-purple-700/40 bg-purple-950/20 text-slate-100' : 'border-cyan-700/40 bg-cyan-950/20 text-slate-100'}`}>
                  {message.role === 'assistant' ? <ReactMarkdown className="prose prose-invert max-w-none text-sm">{message.content}</ReactMarkdown> : message.content}
                </div>
                {message.role === 'user' ? <div className="mt-1 rounded-xl bg-cyan-600/20 p-2"><Shield className="h-4 w-4 text-cyan-300" /></div> : null}
              </div>
            ))}
          </div>

          <div className="mt-4 flex gap-3">
            <input className="field" value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="Ask ARIA anything about your monitored assets…" />
            <button type="button" className="btn-primary" disabled={!prompt || chatMutation.isPending} onClick={() => chatMutation.mutate()}>
              {chatMutation.isPending ? <Spinner /> : <Send className="h-4 w-4" />}
            </button>
          </div>
        </div>
      </div>

      <div className="panel p-5">
        <div className="flex items-center justify-between">
          <p className="section-title">Alerts Feed</p>
          <button type="button" className="btn-secondary" onClick={() => markAllAriaAlertsSeen().then(() => queryClient.invalidateQueries({ queryKey: ['aria', 'alerts'] }))}>Mark all seen</button>
        </div>
        <div className="mt-4 grid gap-3">
          {(alertsQuery.data || []).map((alert) => (
            <div key={alert.id} className={`rounded-xl border p-4 ${alert.seen ? 'border-border bg-slate-950/40' : 'border-red-800/50 bg-red-950/20'}`}>
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div>
                  <div className="flex items-center gap-3">
                    <RiskBadge level={alert.risk_level} />
                    <p className="text-sm font-medium text-slate-100">{alert.title}</p>
                  </div>
                  <p className="mt-2 text-sm text-slate-300">{alert.message}</p>
                  <p className="mt-2 text-xs text-slate-500">{alert.asset_value} • {formatDate(alert.created_at)}</p>
                </div>
                {!alert.seen ? <button type="button" className="btn-secondary" onClick={() => markAriaAlertSeen(alert.id).then(() => queryClient.invalidateQueries({ queryKey: ['aria', 'alerts'] }))}>Mark seen</button> : null}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
