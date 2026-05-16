import { useMemo, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { BarChart, Bar, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { clearCaches, getAuditLogs, getCacheStats, getMetrics } from '../api/admin'
import Spinner from '../components/ui/Spinner'
import { downloadCsv, formatDate } from '../lib/utils'

function parseMetrics(text) {
  return String(text || '')
    .split('\n')
    .filter((line) => line.startsWith('riskintel_requests_total'))
    .map((line) => {
      const match = line.match(/path="([^"]+)"\}\s+(\d+)/)
      return match ? { path: match[1], count: Number(match[2]) } : null
    })
    .filter(Boolean)
}

export default function Admin() {
  const [tab, setTab] = useState('Audit Logs')
  const [limit, setLimit] = useState(100)
  const [rawMetrics, setRawMetrics] = useState(false)
  const auditQuery = useQuery({ queryKey: ['admin', 'audit', limit], queryFn: () => getAuditLogs(limit) })
  const cacheQuery = useQuery({ queryKey: ['admin', 'cache'], queryFn: getCacheStats })
  const metricsQuery = useQuery({ queryKey: ['admin', 'metrics'], queryFn: getMetrics })
  const clearMutation = useMutation({ mutationFn: clearCaches })
  const chartData = useMemo(() => parseMetrics(metricsQuery.data), [metricsQuery.data])

  return (
    <div className="space-y-6">
      <div className="flex gap-3">
        {['Audit Logs', 'Cache', 'Metrics'].map((item) => <button key={item} type="button" className={tab === item ? 'btn-primary' : 'btn-secondary'} onClick={() => setTab(item)}>{item}</button>)}
      </div>

      {tab === 'Audit Logs' ? (
        <div className="panel p-5">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <select className="field max-w-40" value={limit} onChange={(event) => setLimit(Number(event.target.value))}><option value={50}>50</option><option value={100}>100</option><option value={500}>500</option></select>
            <button type="button" className="btn-secondary" onClick={() => downloadCsv('audit-logs.csv', [['timestamp', 'actor', 'role', 'action', 'target_type', 'target_id'], ...(auditQuery.data?.results || []).map((row) => [row.created_at, row.actor, row.role, row.action, row.target_type, row.target_id || ''])])}>Export CSV</button>
          </div>
          <div className="overflow-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="text-slate-400"><tr><th className="px-4 py-3">Timestamp</th><th className="px-4 py-3">Actor</th><th className="px-4 py-3">Role</th><th className="px-4 py-3">Action</th><th className="px-4 py-3">Target Type</th><th className="px-4 py-3">Target ID</th></tr></thead>
              <tbody>
                {(auditQuery.data?.results || []).map((row) => (
                  <tr key={row.id} className="border-t border-border">
                    <td className="px-4 py-3 text-slate-300">{formatDate(row.created_at)}</td>
                    <td className="px-4 py-3 text-slate-300">{row.actor}</td>
                    <td className="px-4 py-3 text-slate-300">{row.role}</td>
                    <td className="px-4 py-3 text-slate-300">{row.action}</td>
                    <td className="px-4 py-3 text-slate-300">{row.target_type}</td>
                    <td className="px-4 py-3 text-slate-300">{row.target_id || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {tab === 'Cache' ? (
        <div className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {Object.entries(cacheQuery.data?.engine || {}).map(([key, value]) => (
              <div key={key} className="panel p-5"><p className="section-title">{key}</p><p className="mt-4 font-mono text-2xl">{value}</p></div>
            ))}
            <div className="panel p-5"><p className="section-title">threat_intel_cache</p><p className="mt-4 font-mono text-2xl">{cacheQuery.data?.threat_intel_cache || 0}</p></div>
            <div className="panel p-5"><p className="section-title">response_cache</p><p className="mt-4 font-mono text-2xl">{cacheQuery.data?.response_cache || 0}</p></div>
          </div>
          <button type="button" className="btn-danger" disabled={clearMutation.isPending} onClick={() => clearMutation.mutate()}>Clear All Caches</button>
        </div>
      ) : null}

      {tab === 'Metrics' ? (
        <div className="space-y-6">
          <div className="flex justify-end">
            <button type="button" className="btn-secondary" onClick={() => setRawMetrics((value) => !value)}>{rawMetrics ? 'Show chart' : 'Show raw text'}</button>
          </div>
          {metricsQuery.isLoading ? <div className="panel p-6"><Spinner /></div> : null}
          {rawMetrics ? (
            <div className="panel p-5"><pre className="overflow-auto text-xs text-slate-300">{metricsQuery.data}</pre></div>
          ) : (
            <div className="panel p-5">
              <div className="h-96">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData}>
                    <CartesianGrid stroke="#1e2a3a" strokeDasharray="3 3" />
                    <XAxis dataKey="path" stroke="#64748b" angle={-20} textAnchor="end" height={90} interval={0} />
                    <YAxis stroke="#64748b" />
                    <Tooltip />
                    <Bar dataKey="count" fill="#06b6d4" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>
      ) : null}
    </div>
  )
}
