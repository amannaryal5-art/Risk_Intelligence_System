import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import client from '../api/client'
import Spinner from '../components/ui/Spinner'
import QuickIOCLookup from '../components/shared/QuickIOCLookup'

export default function ThreatIntel() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(false)

  const summaryQuery = useQuery({
    queryKey: ['threat-intel', 'summary'],
    queryFn: async () => (await client.get('/api/threat-intel/iocs/summary')).data,
  })

  const iocsQuery = useQuery({
    queryKey: ['threat-intel', 'iocs', search],
    queryFn: async () => (await client.get('/api/threat-intel/iocs', { params: { page: 1, limit: 50, search } })).data,
  })

  const pullIocs = async () => {
    setLoading(true)
    try {
      await client.post('/api/threat-intel/auto-pull')
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['threat-intel', 'summary'] }),
        queryClient.invalidateQueries({ queryKey: ['threat-intel', 'iocs'] }),
      ])
    } finally {
      setLoading(false)
    }
  }

  const summary = summaryQuery.data
  const rows = iocsQuery.data?.results || []

  return (
    <div className="space-y-6">
      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <div className="panel p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="section-title">IOC Database</p>
            <button type="button" className="btn-primary" disabled={loading} onClick={pullIocs}>
              {loading ? <Spinner /> : null}
              Auto-Pull Latest IOCs
            </button>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-4 text-sm text-slate-300">
            <div className="rounded-xl border border-border bg-slate-950/50 p-4">Total IOCs: {summary?.total || 0}</div>
            <div className="rounded-xl border border-border bg-slate-950/50 p-4">IPs: {summary?.by_type?.ip || 0}</div>
            <div className="rounded-xl border border-border bg-slate-950/50 p-4">Domains: {summary?.by_type?.domain || 0}</div>
            <div className="rounded-xl border border-border bg-slate-950/50 p-4">Hashes: {summary?.by_type?.hash || 0}</div>
          </div>
          <input className="field mt-4" placeholder="Search IOC value" value={search} onChange={(event) => setSearch(event.target.value)} />
          <div className="mt-4 overflow-hidden rounded-2xl border border-border">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-slate-950/80 text-slate-400">
                <tr>
                  <th className="px-4 py-3">IOC Value</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">Added</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id} className="border-t border-border bg-surface/70">
                    <td className="px-4 py-3 font-mono text-slate-200">{row.value}</td>
                    <td className="px-4 py-3 text-slate-300">{row.type}</td>
                    <td className="px-4 py-3 text-slate-300">{row.source}</td>
                    <td className="px-4 py-3 text-slate-300">{row.confidence}</td>
                    <td className="px-4 py-3 text-slate-500">{row.updated_at}</td>
                  </tr>
                ))}
                {!rows.length ? (
                  <tr>
                    <td colSpan="5" className="px-4 py-8 text-center text-slate-500">No IOC rows returned yet.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </div>
        <QuickIOCLookup />
      </div>
    </div>
  )
}
