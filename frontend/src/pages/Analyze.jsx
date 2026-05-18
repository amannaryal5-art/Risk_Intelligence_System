import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { analyzeText } from '../api/analysis'
import client from '../api/client'
import AnalyzeResultCard from '../components/shared/AnalyzeResultCard'
import Spinner from '../components/ui/Spinner'

export default function Analyze() {
  const [mode, setMode] = useState('manual')
  const [text, setText] = useState('')

  const manualMutation = useMutation({
    mutationFn: () => analyzeText({ text }),
    onError: (error) => toast.error(error.response?.data?.detail || 'Text analysis failed'),
  })

  const autoMutation = useMutation({
    mutationFn: async () => (await client.post('/api/analyze/auto-scan-all')).data,
    onError: (error) => toast.error(error.response?.data?.detail || 'Auto case scan failed'),
  })

  return (
    <div className="space-y-6">
      <div className="flex gap-3">
        <button type="button" className={mode === 'manual' ? 'btn-primary' : 'btn-secondary'} onClick={() => setMode('manual')}>
          Manual Mode
        </button>
        <button type="button" className={mode === 'auto' ? 'btn-primary' : 'btn-secondary'} onClick={() => setMode('auto')}>
          Auto Scan Mode
        </button>
      </div>

      {mode === 'manual' ? (
        <div className="space-y-6">
          <div className="panel p-5">
            <textarea className="field min-h-48" value={text} onChange={(event) => setText(event.target.value)} placeholder="Paste suspicious text, email, message, or transcript..." />
            <div className="mt-4 flex justify-end">
              <button type="button" className="btn-primary" disabled={!text || manualMutation.isPending} onClick={() => manualMutation.mutate()}>
                {manualMutation.isPending ? <Spinner /> : null}
                Analyze
              </button>
            </div>
          </div>
          <AnalyzeResultCard result={manualMutation.data} />
        </div>
      ) : (
        <div className="space-y-6">
          <div className="panel p-5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="section-title">Case Auto Analysis</p>
                <p className="mt-2 text-sm text-slate-400">Scan recent case content, extract IOCs, and persist live IOC records automatically.</p>
              </div>
              <button type="button" className="btn-primary" disabled={autoMutation.isPending} onClick={() => autoMutation.mutate()}>
                {autoMutation.isPending ? <Spinner /> : null}
                Scan All Cases for IOCs
              </button>
            </div>
          </div>

          {autoMutation.data ? (
            <div className="panel p-5">
              <div className="grid gap-4 md:grid-cols-3 text-sm text-slate-300">
                <div className="rounded-xl border border-border bg-slate-950/50 p-4">Cases scanned: {autoMutation.data.cases_scanned}</div>
                <div className="rounded-xl border border-border bg-slate-950/50 p-4">IOCs extracted: {autoMutation.data.iocs_extracted}</div>
                <div className="rounded-xl border border-border bg-slate-950/50 p-4">Risks found: {autoMutation.data.risks_found}</div>
              </div>
              <div className="mt-4 overflow-hidden rounded-2xl border border-border">
                <table className="min-w-full text-left text-sm">
                  <thead className="bg-slate-950/80 text-slate-400">
                    <tr>
                      <th className="px-4 py-3">Case ID</th>
                      <th className="px-4 py-3">IOCs found</th>
                      <th className="px-4 py-3">Risk level</th>
                      <th className="px-4 py-3">Action taken</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(autoMutation.data.results || []).map((row) => (
                      <tr key={row.case_id} className="border-t border-border bg-surface/70">
                        <td className="px-4 py-3 font-mono text-slate-200">{row.case_id}</td>
                        <td className="px-4 py-3 text-slate-300">{row.iocs_found}</td>
                        <td className="px-4 py-3 text-slate-300">{row.risk_level}</td>
                        <td className="px-4 py-3 text-slate-300">{row.action_taken}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}
        </div>
      )}
    </div>
  )
}
