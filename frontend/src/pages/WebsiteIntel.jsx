import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import client from '../api/client'
import Spinner from '../components/ui/Spinner'

export default function WebsiteIntel() {
  const queryClient = useQueryClient()
  const [running, setRunning] = useState(false)
  const scansQuery = useQuery({
    queryKey: ['website-intel', 'recent-scans'],
    queryFn: async () => (await client.get('/api/website-intel/recent-scans')).data,
  })

  const scanAll = async () => {
    setRunning(true)
    try {
      await client.post('/api/website-intel/auto-scan')
      await queryClient.invalidateQueries({ queryKey: ['website-intel', 'recent-scans'] })
    } finally {
      setRunning(false)
    }
  }

  const rows = scansQuery.data || []

  return (
    <div className="space-y-6">
      <div className="panel p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="section-title">Registered Domain Automation</p>
          <button type="button" className="btn-primary" disabled={running} onClick={scanAll}>
            {running ? <Spinner /> : null}
            Scan All Domain Assets
          </button>
        </div>
      </div>

      <div className="panel p-5">
        <p className="section-title">Recent Scans</p>
        <div className="mt-4 overflow-hidden rounded-2xl border border-border">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-950/80 text-slate-400">
              <tr>
                <th className="px-4 py-3">Domain</th>
                <th className="px-4 py-3">Scan Date</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">Malicious</th>
                <th className="px-4 py-3">Verdict</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className="border-t border-border bg-surface/70">
                  <td className="px-4 py-3 font-mono text-slate-200">{row.domain}</td>
                  <td className="px-4 py-3 text-slate-300">{row.scanned_at}</td>
                  <td className="px-4 py-3 text-slate-300">{row.score ?? 0}</td>
                  <td className="px-4 py-3 text-slate-300">{row.malicious ? 'Yes' : 'No'}</td>
                  <td className="px-4 py-3 text-slate-300">{row.verdict || 'unknown'}</td>
                </tr>
              ))}
              {!rows.length ? (
                <tr>
                  <td colSpan="5" className="px-4 py-8 text-center text-slate-500">No recent scans yet.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
