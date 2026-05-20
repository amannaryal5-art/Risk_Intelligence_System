import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import client from '../api/client'
import { listCases } from '../api/cases'
import RiskBadge from '../components/ui/RiskBadge'
import CaseBadge from '../components/ui/CaseBadge'
import Spinner from '../components/ui/Spinner'
import { formatDate } from '../lib/utils'

export default function Cases() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [filters, setFilters] = useState({ search: '', status: '', severity: '', assigned_to: '', limit: 50 })

  const casesQuery = useQuery({
    queryKey: ['cases', filters],
    queryFn: () => listCases(filters),
    refetchInterval: 30000,
    refetchIntervalInBackground: true,
  })

  const autoCreateMutation = useMutation({
    mutationFn: async () => (await client.post('/api/cases/auto-create-from-alerts')).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      toast.success('Auto-created cases from alerts')
    },
  })

  const rows = casesQuery.data?.results || []

  return (
    <div className="space-y-6">
      <div className="panel p-5">
        <div className="grid gap-3 xl:grid-cols-[1.6fr_repeat(3,1fr)_auto]">
          <input className="field" placeholder="Search cases" value={filters.search} onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))} />
          <select className="field" value={filters.status} onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))}>
            <option value="">All status</option><option value="new">new</option><option value="triaged">triaged</option><option value="escalated">escalated</option><option value="closed">closed</option>
          </select>
          <select className="field" value={filters.severity} onChange={(event) => setFilters((current) => ({ ...current, severity: event.target.value }))}>
            <option value="">All severity</option><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option>
          </select>
          <select className="field" value={filters.limit} onChange={(event) => setFilters((current) => ({ ...current, limit: Number(event.target.value) }))}>
            {[25, 50, 100].map((value) => <option key={value} value={value}>{value} rows</option>)}
          </select>
          <button type="button" className="btn-primary" disabled={autoCreateMutation.isPending} onClick={() => autoCreateMutation.mutate()}>
            {autoCreateMutation.isPending ? <Spinner /> : null}
            Auto-Create Cases from Critical Alerts
          </button>
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-border">
        <div className="overflow-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-950/80 text-slate-400">
              <tr>
                {['ID', 'Title', 'Severity', 'Source', 'Status', 'Assigned To', 'Created', 'Updated', 'Actions'].map((heading) => (
                  <th key={heading} className="px-4 py-3 font-mono text-[10px] tracking-[0.18em]">{heading}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const severity = String(row.severity || '').toUpperCase()
                const border = severity === 'CRITICAL' ? 'border-l-[3px] border-red-500' : severity === 'HIGH' ? 'border-l-[3px] border-orange-500' : severity === 'MEDIUM' ? 'border-l-[3px] border-yellow-500' : ''
                const source = row.source_type || 'manual'
                return (
                  <tr
                    key={row.id}
                    className={`border-t border-border bg-surface/70 cursor-pointer hover:bg-cyber-cyan/5 ${border}`}
                    onClick={() => navigate(`/cases/${row.id}`)}
                  >
                    <td className="px-4 py-3 font-mono text-slate-400">{row.id}</td>
                    <td className="px-4 py-3 font-mono text-slate-100">{row.title}</td>
                    <td className="px-4 py-3"><RiskBadge level={row.severity} /></td>
                    <td className="px-4 py-3">
                      <span className={`rounded border px-2 py-1 font-mono text-[10px] ${source === 'device_scan' ? 'border-emerald-500/30 text-emerald-400' : source.includes('intelligence') ? 'border-cyan-500/30 text-cyan-300' : source.startsWith('auto') ? 'border-yellow-500/30 text-yellow-300' : 'border-border text-slate-400'}`}>
                        {String(source).toUpperCase().replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-4 py-3"><CaseBadge status={row.status} /></td>
                    <td className="px-4 py-3 text-slate-300">{row.assigned_to || '-'}</td>
                    <td className="px-4 py-3 font-mono text-[11px] text-slate-500">{formatDate(row.created_at)}</td>
                    <td className="px-4 py-3 font-mono text-[11px] text-slate-500">{formatDate(row.updated_at)}</td>
                    <td className="px-4 py-3">
                      <button
                        type="button"
                        className="btn-secondary px-3 py-2 font-mono text-[10px]"
                        onClick={(event) => {
                          event.stopPropagation()
                          navigate(`/cases/${row.id}`)
                        }}
                      >
                        [ OPEN ]
                      </button>
                    </td>
                  </tr>
                )
              })}
              {!rows.length ? (
                <tr>
                  <td colSpan="9" className="px-4 py-10 text-center text-slate-500">No cases yet. Run AutoPilot or auto-create from alerts.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
