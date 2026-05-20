import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import ReactMarkdown from 'react-markdown'
import { addAriaAsset, ariaChat, getAriaAssets, getAriaStats } from '../api/aria'
import client from '../api/client'
import RiskBadge from '../components/ui/RiskBadge'
import Spinner from '../components/ui/Spinner'
import { formatDate } from '../lib/utils'

const CHIPS = [
  "what's my risk score",
  'show critical assets',
  'run full scan',
  "what's suspicious",
  "which feeds are down",
]

export default function ARIA() {
  const [draft, setDraft] = useState({ name: '', type: 'domain', value: '', scan_interval_hours: 6 })
  const [messages, setMessages] = useState([])
  const [prompt, setPrompt] = useState('')

  const assetsQuery = useQuery({ queryKey: ['aria', 'assets'], queryFn: getAriaAssets })
  const statsQuery = useQuery({ queryKey: ['aria', 'stats'], queryFn: getAriaStats })

  useEffect(() => {
    let stopped = false
    const loadOpeningMessage = async () => {
      try {
        const [assets, cases, deviceScan] = await Promise.all([
          client.get('/api/assets').then((res) => res.data),
          client.get('/api/v1/cases', { params: { status: 'new', limit: 200 } }).then((res) => res.data),
          client.get('/api/device/scan/latest').then((res) => res.data),
        ])
        if (stopped) return
        const criticalAssets = (assets || []).filter((asset) => Number(asset.risk_score || 0) >= 80)
        const highAssets = (assets || []).filter((asset) => Number(asset.risk_score || 0) >= 60 && Number(asset.risk_score || 0) < 80)
        const openCasesCount = (cases?.results || cases || []).length
        const deviceRisk = Number(deviceScan?.overall_risk_score || 0)
        const hostname = deviceScan?.hostname || 'unknown-host'
        let content = 'ARIA > System online. '
        if (criticalAssets.length > 0) {
          content += `CRITICAL ALERT: ${criticalAssets.length} asset(s) need immediate attention. Highest risk: ${criticalAssets[0].label || criticalAssets[0].name} (${criticalAssets[0].risk_score}/100).`
        } else if (highAssets.length > 0) {
          content += `High-risk assets detected: ${highAssets.map((asset) => asset.label || asset.name).join(', ')}. Review recommended.`
        } else if (deviceRisk > 50) {
          content += `Host ${hostname} shows elevated device risk at ${deviceRisk}/100. Run a full review.`
        } else {
          content += `All ${(assets || []).length} monitored assets are within acceptable parameters. Device ${hostname}: ${deviceRisk}/100. ${openCasesCount > 0 ? `${openCasesCount} open case(s) pending review.` : 'No open cases. Posture SECURE.'}`
        }
        setMessages([{ role: 'assistant', content }])
      } catch {
        if (!stopped) {
          setMessages([{ role: 'assistant', content: 'ARIA > System online. Unable to load live context. Check feed status.' }])
        }
      }
    }
    loadOpeningMessage()
    return () => {
      stopped = true
    }
  }, [])

  const addAssetMutation = useMutation({
    mutationFn: () => addAriaAsset({ ...draft, scan_interval_hours: Number(draft.scan_interval_hours) }),
    onSuccess: () => setDraft({ name: '', type: 'domain', value: '', scan_interval_hours: 6 }),
  })

  const chatMutation = useMutation({
    mutationFn: (message) => ariaChat({ message, conversation_history: messages }),
    onSuccess: (data, sentMessage) => {
      const reply = data.reply || data.response
      setMessages((current) => [...current, { role: 'user', content: sentMessage }, { role: 'assistant', content: reply }])
      setPrompt('')
    },
  })

  const sendMessage = (message) => {
    const value = String(message || prompt).trim()
    if (!value) return
    chatMutation.mutate(value)
  }

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
                    <p className="font-mono text-sm text-slate-100">{asset.label || asset.name}</p>
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

        <div className="panel-elevated flex min-h-[700px] flex-col overflow-hidden">
          <div className="border-b border-cyber-cyan/15 px-5 py-4">
            <p className="section-title">AI Analyst Chat</p>
            <p className="mt-2 text-sm text-slate-400">Live asset posture, feed health, and device telemetry in terminal form.</p>
          </div>

          <div className="flex-1 overflow-auto bg-slate-950/70 px-5 py-4">
            {messages.map((message, index) => (
              <div
                key={index}
                className="mb-3 text-sm"
                style={
                  message.role === 'assistant'
                    ? {
                        borderLeft: '2px solid #00d4ff',
                        padding: '10px 14px',
                        background: 'rgba(0,212,255,0.04)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '12px',
                        lineHeight: 1.8,
                        borderRadius: '0 4px 4px 0',
                      }
                    : {
                        borderLeft: '2px solid #2a5570',
                        padding: '10px 14px',
                        background: 'rgba(0,0,0,0.3)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '12px',
                        marginLeft: 16,
                      }
                }
              >
                <span style={{ color: message.role === 'assistant' ? '#00d4ff' : '#2a5570', fontWeight: 600 }}>
                  {message.role === 'assistant' ? 'ARIA > ' : '[USR] > '}
                </span>
                {message.role === 'assistant' ? <ReactMarkdown className="prose prose-invert inline max-w-none">{message.content}</ReactMarkdown> : message.content}
              </div>
            ))}
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              borderTop: '1px solid rgba(0,212,255,0.15)',
              padding: '10px 14px',
              gap: 8,
              background: 'var(--bg-secondary)',
            }}
          >
            <span
              style={{
                color: '#00d4ff',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                whiteSpace: 'nowrap',
                userSelect: 'none',
              }}
            >
              root@crie:~$
            </span>
            <input
              className="w-full bg-transparent text-sm text-slate-100 outline-none"
              style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}
              value={prompt}
              onChange={(event) => setPrompt(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') sendMessage()
              }}
              placeholder=""
            />
            <button type="button" className="btn-primary" disabled={!prompt.trim() || chatMutation.isPending} onClick={() => sendMessage()}>
              {chatMutation.isPending ? <Spinner /> : 'SEND'}
            </button>
          </div>

          <div className="flex flex-wrap gap-2 border-t border-cyber-cyan/10 px-4 py-3">
            {CHIPS.map((chip) => (
              <button
                key={chip}
                type="button"
                onClick={() => sendMessage(chip)}
                className="border border-cyber-cyan/20 bg-transparent px-2 py-1 font-mono text-[10px] text-slate-400 hover:text-cyber-cyan"
              >
                {chip}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
