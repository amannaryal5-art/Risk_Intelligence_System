import { useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Activity } from 'lucide-react'
import client from '../api/client'
import Spinner from '../components/ui/Spinner'

export default function FusionScan() {
  const mutation = useMutation({
    mutationFn: async () => (await client.post('/api/fusion-scan/auto')).data,
    onError: (err) => toast.error(err.response?.data?.detail || 'Fusion scan failed'),
  })

  return (
    <div className="space-y-6">
      <div className="panel p-5">
        <div className="mb-4 flex items-center gap-3">
          <Activity className="h-5 w-5 text-cyan-400" />
          <p className="font-mono text-lg text-slate-50">Fusion Scan</p>
        </div>
        <p className="text-sm text-slate-400">Run auto fusion across the latest collected IOCs and combine text, web, and feed risk signals.</p>
        <button type="button" className="btn-primary mt-4" disabled={mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? <Spinner /> : null}
          Run Auto Fusion on Latest IOCs
        </button>
      </div>

      {mutation.data ? (
        <div className="panel p-5">
          <div className="grid gap-4 md:grid-cols-3 text-sm text-slate-300">
            <div className="rounded-xl border border-border bg-slate-950/50 p-4">IOCs processed: {mutation.data.iocs_processed}</div>
            <div className="rounded-xl border border-border bg-slate-950/50 p-4">High fusion risk: {mutation.data.high_fusion_risk}</div>
            <div className="rounded-xl border border-border bg-slate-950/50 p-4">Cases created: {mutation.data.cases_created}</div>
          </div>
          <div className="mt-4 overflow-hidden rounded-2xl border border-border">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-slate-950/80 text-slate-400">
                <tr>
                  <th className="px-4 py-3">IOC</th>
                  <th className="px-4 py-3">Text Risk</th>
                  <th className="px-4 py-3">Web Risk</th>
                  <th className="px-4 py-3">Feed Risk</th>
                  <th className="px-4 py-3">Fusion Score</th>
                </tr>
              </thead>
              <tbody>
                {(mutation.data.results || []).map((row) => (
                  <tr key={row.ioc} className="border-t border-border bg-surface/70">
                    <td className="px-4 py-3 font-mono text-slate-200">{row.ioc}</td>
                    <td className="px-4 py-3 text-slate-300">{row.text_risk}</td>
                    <td className="px-4 py-3 text-slate-300">{row.web_risk}</td>
                    <td className="px-4 py-3 text-slate-300">{row.feed_risk}</td>
                    <td className="px-4 py-3 text-slate-300">{row.fusion_score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  )
}
