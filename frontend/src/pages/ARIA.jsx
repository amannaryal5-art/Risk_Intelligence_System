import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import ReactMarkdown from 'react-markdown'
import { Bot, Send, Shield } from 'lucide-react'
import { addAriaAsset, ariaChat, getAriaAssets, getAriaStats } from '../api/aria'
import RiskBadge from '../components/ui/RiskBadge'
import Spinner from '../components/ui/Spinner'
import { formatDate } from '../lib/utils'

export default function ARIA() {
  const [draft, setDraft] = useState({ name: '', type: 'domain', value: '', scan_interval_hours: 6 })
  const [messages, setMessages] = useState([{ role: 'assistant', content: 'ARIA online. Ask for asset posture, risk summaries, or threat triage support.' }])
  const [prompt, setPrompt] = useState('')

  const assetsQuery = useQuery({ queryKey: ['aria', 'assets'], queryFn: getAriaAssets })
  const statsQuery = useQuery({ queryKey: ['aria', 'stats'], queryFn: getAriaStats })

  const addAssetMutation = useMutation({
    mutationFn: () => addAriaAsset({ ...draft, scan_interval_hours: Number(draft.scan_interval_hours) }),
    onSuccess: () => setDraft({ name: '', type: 'domain', value: '', scan_interval_hours: 6 }),
  })

  const chatMutation = useMutation({
    mutationFn: () => ariaChat({ message: prompt, conversation_history: messages }),
    onSuccess: (data) => {
      const reply = data.reply || data.response
      setMessages((current) => [...current, { role: 'user', content: prompt }, { role: 'assistant', content: reply }])
      setPrompt('')
    },
  })

  return (
    <div className="space-y-6">
      <div className="grid gap-6 xl:grid-cols-[0.85fr_1.15fr]">
        <div className="panel p-5">
          <div className="flex items-center justify-between">
            <p className="section-title">Asset Monitor</p>
            <button type="button" className="btn-primary" disabled={addAssetMutation.isPending} onClick={() => addAssetMutation.mutate()}>
              Add Asset
            </button>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <input className="field" placeholder="Name" value={draft.name} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} />
            <select className="field" value={draft.type} onChange={(event) => setDraft((current) => ({ ...current, type: event.target.value }))}><option>domain</option><option>ip</option><option>url</option><option>email</option></select>
            <input className="field md:col-span-2" placeholder="Value" value={draft.value} onChange={(event) => setDraft((current) => ({ ...current, value: event.target.value }))} />
          </div>

          <div className="mt-4 rounded-xl border border-border bg-slate-950/50 p-4 text-sm text-slate-300">
            Monitoring {statsQuery.data?.assets_monitored || 0} assets, {statsQuery.data?.unseen_alerts || 0} unseen alerts
          </div>

          <div className="mt-4 space-y-3">
            {(assetsQuery.data || []).map((asset) => (
              <div key={asset.id} className="rounded-xl border border-border bg-slate-950/50 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium text-slate-100">{asset.label || asset.name}</p>
                    <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{asset.type} | {asset.value}</p>
                  </div>
                  <RiskBadge level={asset.risk_level || 'unknown'} />
                </div>
                <p className="mt-3 text-sm text-slate-400">Risk score: {asset.risk_score ?? 'unscanned'}</p>
                <p className="mt-2 text-xs text-slate-500">Last scanned: {formatDate(asset.last_scanned)}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="panel-elevated flex min-h-[700px] flex-col p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="section-title">AI Analyst Chat</p>
              <p className="mt-2 text-sm text-slate-400">Real context from the monitored asset store and live alert state.</p>
            </div>
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
            <input className="field" value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="Ask ARIA anything about your monitored assets..." />
            <button type="button" className="btn-primary" disabled={!prompt || chatMutation.isPending} onClick={() => chatMutation.mutate()}>
              {chatMutation.isPending ? <Spinner /> : <Send className="h-4 w-4" />}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
