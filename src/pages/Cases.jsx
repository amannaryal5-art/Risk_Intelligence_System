import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import { createCase, deleteCase, listCases, updateCase } from '../api/cases'
import RiskBadge from '../components/ui/RiskBadge'
import CaseBadge from '../components/ui/CaseBadge'
import Spinner from '../components/ui/Spinner'
import { downloadCsv, formatDate } from '../lib/utils'
import { useAuthStore } from '../store/authStore'

const blankCase = { title: '', severity: 'medium', status: 'new', assigned_to: '', tags: '', source_type: 'manual', source_value: '', notes: '', ioc_type: '', ioc_value: '', risk_score: 50 }

export default function Cases() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const user = useAuthStore((state) => state.user)
  const canEdit = user?.role !== 'viewer'
  const [filters, setFilters] = useState({ search: '', status: '', severity: '', assigned_to: '', limit: 50 })
  const [selectedIds, setSelectedIds] = useState([])
  const [showModal, setShowModal] = useState(false)
  const [draft, setDraft] = useState(blankCase)

  const casesQuery = useQuery({
    queryKey: ['cases', filters],
    queryFn: () => listCases(filters),
    refetchInterval: 30000,
    refetchIntervalInBackground: true,
  })

  const createMutation = useMutation({
    mutationFn: () => createCase({ ...draft, tags: draft.tags.split(',').map((item) => item.trim()).filter(Boolean), recommendations: [], findings: {}, scan_result: {} }),
    onSuccess: () => {
      setShowModal(false)
      setDraft(blankCase)
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      toast.success('Case created')
    },
    onError: (error) => toast.error(error.response?.data?.detail || 'Case creation failed'),
  })

  const bulkStatus = useMutation({
    mutationFn: async (status) => Promise.all(selectedIds.map((id) => updateCase(id, { status }))),
    onSuccess: () => {
      setSelectedIds([])
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      toast.success('Cases updated')
    },
  })

  const bulkDelete = useMutation({
    mutationFn: async () => Promise.all(selectedIds.map((id) => deleteCase(id))),
    onSuccess: () => {
      setSelectedIds([])
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      toast.success('Cases deleted')
    },
  })

  const rows = casesQuery.data?.results || []
  const allSelected = useMemo(() => rows.length && rows.every((row) => selectedIds.includes(row.id)), [rows, selectedIds])

  return (
    <div className="space-y-6">
      <div className="panel p-5">
        <div className="grid gap-3 xl:grid-cols-[1.4fr_repeat(4,1fr)_auto]">
          <input className="field" placeholder="Search cases" value={filters.search} onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))} />
          <select className="field" value={filters.status} onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))}>
            <option value="">All status</option><option value="new">new</option><option value="triaged">triaged</option><option value="escalated">escalated</option><option value="closed">closed</option>
          </select>
          <select className="field" value={filters.severity} onChange={(event) => setFilters((current) => ({ ...current, severity: event.target.value }))}>
            <option value="">All severity</option><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option>
          </select>
          <input className="field" placeholder="Assigned to" value={filters.assigned_to} onChange={(event) => setFilters((current) => ({ ...current, assigned_to: event.target.value }))} />
          <select className="field" value={filters.limit} onChange={(event) => setFilters((current) => ({ ...current, limit: Number(event.target.value) }))}>
            {[25, 50, 100, 200].map((value) => <option key={value} value={value}>{value} rows</option>)}
          </select>
          <button type="button" className="btn-primary" disabled={!canEdit} onClick={() => setShowModal(true)}>New Case</button>
        </div>

        <div className="mt-4 flex flex-wrap gap-3">
          <button type="button" className="btn-secondary" disabled={!selectedIds.length || !canEdit || bulkStatus.isPending} onClick={() => bulkStatus.mutate('triaged')}>Bulk Triaged</button>
          <button type="button" className="btn-danger" disabled={!selectedIds.length || !canEdit || bulkDelete.isPending} onClick={() => bulkDelete.mutate()}>Bulk Delete</button>
          <button type="button" className="btn-secondary" disabled={!rows.length} onClick={() => downloadCsv('cases.csv', [['ID', 'Title', 'Severity', 'Status', 'Assigned To'], ...rows.map((row) => [row.id, row.title, row.severity, row.status, row.assigned_to || ''])])}>Export CSV</button>
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-border">
        <div className="overflow-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-950/80 text-slate-400">
              <tr>
                <th className="px-4 py-3"><input type="checkbox" checked={!!allSelected} onChange={() => setSelectedIds(allSelected ? [] : rows.map((row) => row.id))} /></th>
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Assigned To</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3">Updated</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className="border-t border-border bg-surface/70">
                  <td className="px-4 py-3"><input type="checkbox" checked={selectedIds.includes(row.id)} onChange={() => setSelectedIds((current) => current.includes(row.id) ? current.filter((id) => id !== row.id) : [...current, row.id])} /></td>
                  <td className="px-4 py-3 font-mono text-slate-100">{row.id}</td>
                  <td className="px-4 py-3 text-slate-100">{row.title}</td>
                  <td className="px-4 py-3"><RiskBadge level={row.severity} /></td>
                  <td className="px-4 py-3"><CaseBadge status={row.status} /></td>
                  <td className="px-4 py-3 text-slate-300">{row.assigned_to || '—'}</td>
                  <td className="px-4 py-3 text-slate-400">{formatDate(row.created_at)}</td>
                  <td className="px-4 py-3 text-slate-400">{formatDate(row.updated_at)}</td>
                  <td className="px-4 py-3"><button type="button" className="btn-secondary px-3 py-2" onClick={() => navigate(`/cases/${row.id}`)}>Open</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showModal ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="panel-elevated w-full max-w-3xl p-6">
            <h3 className="font-mono text-xl text-slate-50">New Case</h3>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <input className="field md:col-span-2" placeholder="Title*" value={draft.title} onChange={(event) => setDraft((current) => ({ ...current, title: event.target.value }))} />
              <select className="field" value={draft.severity} onChange={(event) => setDraft((current) => ({ ...current, severity: event.target.value }))}><option>low</option><option>medium</option><option>high</option><option>critical</option></select>
              <select className="field" value={draft.status} onChange={(event) => setDraft((current) => ({ ...current, status: event.target.value }))}><option>new</option><option>triaged</option><option>escalated</option><option>closed</option></select>
              <input className="field" placeholder="Assigned To" value={draft.assigned_to} onChange={(event) => setDraft((current) => ({ ...current, assigned_to: event.target.value }))} />
              <input className="field" placeholder="Tags, comma separated" value={draft.tags} onChange={(event) => setDraft((current) => ({ ...current, tags: event.target.value }))} />
              <input className="field" placeholder="Source Type" value={draft.source_type} onChange={(event) => setDraft((current) => ({ ...current, source_type: event.target.value }))} />
              <input className="field" placeholder="Source Value" value={draft.source_value} onChange={(event) => setDraft((current) => ({ ...current, source_value: event.target.value }))} />
              <input className="field" placeholder="IOC Type" value={draft.ioc_type} onChange={(event) => setDraft((current) => ({ ...current, ioc_type: event.target.value }))} />
              <input className="field" placeholder="IOC Value" value={draft.ioc_value} onChange={(event) => setDraft((current) => ({ ...current, ioc_value: event.target.value }))} />
              <div className="md:col-span-2">
                <label className="mb-2 block text-sm text-slate-400">Risk Score: {draft.risk_score}</label>
                <input className="w-full" type="range" min="0" max="100" value={draft.risk_score} onChange={(event) => setDraft((current) => ({ ...current, risk_score: Number(event.target.value) }))} />
              </div>
              <textarea className="field md:col-span-2 min-h-32" placeholder="Notes" value={draft.notes} onChange={(event) => setDraft((current) => ({ ...current, notes: event.target.value }))} />
            </div>
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" className="btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
              <button type="button" className="btn-primary" disabled={!draft.title || createMutation.isPending} onClick={() => createMutation.mutate()}>
                {createMutation.isPending ? <Spinner /> : null}
                Create Case
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}
