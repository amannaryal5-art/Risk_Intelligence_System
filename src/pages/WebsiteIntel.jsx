import { useEffect, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { BarChart3 } from 'lucide-react'
import { getWebsiteIntel, traceWebsite } from '../api/threatIntel'
import RiskBadge from '../components/ui/RiskBadge'
import ScoreRing from '../components/ui/ScoreRing'
import Spinner from '../components/ui/Spinner'
import { formatDate, pushHistory, readHistory } from '../lib/utils'

export default function WebsiteIntel() {
  const [tab, setTab] = useState('Quick Scan')
  const [url, setUrl] = useState('')
  const [trace, setTrace] = useState({ url: '', max_pages: 120, max_depth: 4, include_external: false, exhaustive: true })
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    if (!tab || !elapsed) return
  }, [tab, elapsed])

  const quickScan = useMutation({
    mutationFn: () => getWebsiteIntel({ url }),
    onSuccess: (data) => pushHistory('crie-website-history', data, 10),
    onError: (error) => toast.error(error.response?.data?.detail || 'Website scan failed'),
  })

  const deepTrace = useMutation({
    mutationFn: () => traceWebsite(trace),
    onMutate: () => setElapsed(0),
    onSuccess: (data) => pushHistory('crie-website-history', data, 10),
    onError: (error) => toast.error(error.response?.data?.detail || 'Deep trace failed'),
  })

  useEffect(() => {
    if (!deepTrace.isPending) return undefined
    const id = window.setInterval(() => setElapsed((value) => value + 1), 1000)
    return () => window.clearInterval(id)
  }, [deepTrace.isPending])

  const history = readHistory('crie-website-history')

  return (
    <div className="space-y-6">
      <div className="flex gap-3">
        {['Quick Scan', 'Deep Trace'].map((item) => (
          <button key={item} type="button" className={tab === item ? 'btn-primary' : 'btn-secondary'} onClick={() => setTab(item)}>{item}</button>
        ))}
      </div>

      {tab === 'Quick Scan' ? (
        <div className="space-y-6">
          <div className="panel p-5">
            <input className="field" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" />
            <button type="button" className="btn-primary mt-4" disabled={!url || quickScan.isPending} onClick={() => quickScan.mutate()}>
              {quickScan.isPending ? <Spinner /> : null}
              Run Quick Scan
            </button>
          </div>
          {quickScan.data ? (
            <div className="panel-elevated p-6">
              <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex items-center gap-6">
                  <ScoreRing score={quickScan.data.riskScore} size={130} />
                  <div>
                    <p className="font-mono text-xl text-slate-50">{quickScan.data.domain}</p>
                    <p className="mt-2 text-sm text-slate-400">Resolved IP: {quickScan.data.ip || 'unknown'}</p>
                    <div className="mt-4">
                      <RiskBadge level={quickScan.data.verdict} />
                    </div>
                  </div>
                </div>
                <div className="rounded-2xl border border-border bg-slate-950/50 p-4 text-sm text-slate-300">
                  <p>{quickScan.data.summary}</p>
                  <p className="mt-3 text-xs text-slate-500">Scanned at {formatDate(new Date().toISOString())}</p>
                </div>
              </div>
              <div className="mt-6 grid gap-4 md:grid-cols-3">
                <div className="panel p-4"><p className="section-title">OTX Pulses</p><p className="mt-3 font-mono text-2xl">{quickScan.data?.feeds?.otx?.pulseCount || 0}</p></div>
                <div className="panel p-4"><p className="section-title">AbuseIPDB Confidence</p><p className="mt-3 font-mono text-2xl">{quickScan.data?.feeds?.abuseipdb?.abuseConfidence || 0}%</p></div>
                <div className="panel p-4"><p className="section-title">VT Malicious</p><p className="mt-3 font-mono text-2xl">{quickScan.data?.feeds?.virustotal?.malicious || 0}</p></div>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}

      {tab === 'Deep Trace' ? (
        <div className="space-y-6">
          <div className="panel p-5">
            <input className="field" value={trace.url} onChange={(event) => setTrace((current) => ({ ...current, url: event.target.value }))} placeholder="https://example.com" />
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <input className="field" type="number" min="1" max="500" value={trace.max_pages} onChange={(event) => setTrace((current) => ({ ...current, max_pages: Number(event.target.value) }))} />
              <input className="field" type="number" min="0" max="8" value={trace.max_depth} onChange={(event) => setTrace((current) => ({ ...current, max_depth: Number(event.target.value) }))} />
              <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={trace.include_external} onChange={(event) => setTrace((current) => ({ ...current, include_external: event.target.checked }))} />Include external</label>
              <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={trace.exhaustive} onChange={(event) => setTrace((current) => ({ ...current, exhaustive: event.target.checked }))} />Exhaustive</label>
            </div>
            <button type="button" className="btn-primary mt-4" disabled={!trace.url || deepTrace.isPending} onClick={() => deepTrace.mutate()}>
              {deepTrace.isPending ? <Spinner /> : null}
              Start Deep Trace
            </button>
            {deepTrace.isPending ? <p className="mt-3 text-sm text-slate-400">Crawling… elapsed {elapsed}s</p> : null}
          </div>
          {deepTrace.data ? (
            <div className="panel-elevated p-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <p className="font-mono text-xl text-slate-50">{deepTrace.data.site_verdict || 'Trace complete'}</p>
                  <p className="mt-2 text-sm text-slate-400">Pages crawled: {deepTrace.data.pages_crawled || 0} • Coverage: {deepTrace.data.coverage || 'n/a'}</p>
                </div>
                <RiskBadge level={deepTrace.data.site_verdict} />
              </div>
              <div className="mt-6 grid gap-6 xl:grid-cols-[1.4fr_1fr]">
                <div className="overflow-hidden rounded-2xl border border-border">
                  <table className="min-w-full text-left text-sm">
                    <thead className="bg-slate-950/80 text-slate-400"><tr><th className="px-4 py-3">Top Risky Pages</th><th className="px-4 py-3">Score</th></tr></thead>
                    <tbody>
                      {(deepTrace.data.risky_pages || deepTrace.data.top_risky_pages || []).map((page, index) => (
                        <tr key={index} className="border-t border-border bg-surface/70">
                          <td className="px-4 py-3 text-slate-300">{page.url || page.path || JSON.stringify(page)}</td>
                          <td className="px-4 py-3 font-mono text-slate-100">{page.score || page.risk_score || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="panel p-4">
                  <p className="section-title">Risk Histogram</p>
                  <div className="mt-4 space-y-3">
                    {(deepTrace.data.risk_distribution || []).map((bucket, index) => (
                      <div key={index}>
                        <div className="flex items-center justify-between text-xs text-slate-400">
                          <span>{bucket.label || bucket.range || `Bucket ${index + 1}`}</span>
                          <span>{bucket.count || 0}</span>
                        </div>
                        <div className="mt-1 h-2 rounded-full bg-slate-900">
                          <div className="h-2 rounded-full bg-cyan-500" style={{ width: `${Math.min(100, (bucket.count || 0) * 10)}%` }} />
                        </div>
                      </div>
                    ))}
                    {!deepTrace.data.risk_distribution?.length ? <div className="text-sm text-slate-400"><BarChart3 className="mb-2 h-4 w-4" />No histogram buckets returned by the backend.</div> : null}
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}

      {history.length ? (
        <div className="panel p-5">
          <p className="section-title">Recent Scans</p>
          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {history.slice(0, 6).map((item, index) => (
              <div key={index} className="rounded-xl border border-border bg-slate-950/50 p-4">
                <p className="font-mono text-sm">{item.domain || item.input}</p>
                <p className="mt-2 text-sm text-slate-400">{item.summary}</p>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  )
}
