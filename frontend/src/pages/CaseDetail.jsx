import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams } from 'react-router-dom'
import toast from 'react-hot-toast'
import { addCaseComment, deleteCase, getCase, updateCase } from '../api/cases'
import RiskBadge from '../components/ui/RiskBadge'
import CaseBadge from '../components/ui/CaseBadge'
import CodeBlock from '../components/ui/CodeBlock'
import Spinner from '../components/ui/Spinner'
import { downloadJson, formatDate } from '../lib/utils'
import { useAuthStore } from '../store/authStore'

export default function CaseDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const user = useAuthStore((state) => state.user)
  const canEdit = user?.role !== 'viewer'
  const [comment, setComment] = useState('')
  const caseQuery = useQuery({ queryKey: ['case', id], queryFn: () => getCase(id) })

  const statusMutation = useMutation({
    mutationFn: (status) => updateCase(id, { status }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['case', id] }),
  })
  const commentMutation = useMutation({
    mutationFn: () => addCaseComment(id, { body: comment }),
    onSuccess: () => {
      setComment('')
      queryClient.invalidateQueries({ queryKey: ['case', id] })
      toast.success('Comment added')
    },
  })
  const deleteMutation = useMutation({
    mutationFn: () => deleteCase(id),
    onSuccess: () => {
      toast.success('Case deleted')
      navigate('/cases')
    },
  })

  const item = caseQuery.data

  if (caseQuery.isLoading) return <div className="panel p-6"><Spinner /></div>
  if (!item) return <div className="panel p-6">Case not found.</div>

  return (
    <div className="space-y-6">
      <div className="panel-elevated p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
          <div>
            <p className="font-mono text-sm text-slate-500">Case #{item.id}</p>
            <h2 className="mt-2 font-mono text-2xl text-slate-50">{item.title}</h2>
            <div className="mt-4 flex flex-wrap gap-3">
              <RiskBadge level={item.severity} />
              <CaseBadge status={item.status} />
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <select className="field max-w-40" value={item.status} disabled={!canEdit || statusMutation.isPending} onChange={(event) => statusMutation.mutate(event.target.value)}>
              <option>new</option><option>triaged</option><option>escalated</option><option>closed</option>
            </select>
            <button type="button" className="btn-secondary" onClick={() => downloadJson(`case-${item.id}.json`, item)}>Export JSON</button>
            <button type="button" className="btn-danger" disabled={!canEdit || deleteMutation.isPending} onClick={() => deleteMutation.mutate()}>Delete</button>
          </div>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-[2fr_1fr]">
        <div className="space-y-6">
          <details className="panel p-5" open>
            <summary className="cursor-pointer text-sm font-medium text-slate-100">Findings JSON</summary>
            <div className="mt-4"><CodeBlock data={item.findings} /></div>
          </details>
          <div className="panel p-5">
            <p className="section-title">Recommendations</p>
            <ul className="mt-4 space-y-3 text-sm text-slate-300">
              {(item.recommendations || []).map((entry, index) => <li key={index}>• {entry}</li>)}
            </ul>
          </div>
          <details className="panel p-5">
            <summary className="cursor-pointer text-sm font-medium text-slate-100">Scan Result JSON</summary>
            <div className="mt-4"><CodeBlock data={item.scan_result} /></div>
          </details>
          <div className="panel p-5">
            <p className="section-title">Timeline</p>
            <div className="mt-4 space-y-4">
              {(item.comments || []).map((entry) => (
                <div key={entry.id} className="rounded-xl border border-border bg-slate-950/50 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm font-medium text-slate-100">{entry.author}</p>
                    <p className="text-xs text-slate-500">{formatDate(entry.created_at)}</p>
                  </div>
                  <p className="mt-2 text-sm text-slate-300">{entry.message}</p>
                </div>
              ))}
            </div>
            <div className="mt-4 space-y-3">
              <textarea
                className="field min-h-24"
                placeholder="Add comment"
                value={comment}
                onChange={(event) => setComment(event.target.value)}
              />
              <button type="button" className="btn-primary" disabled={!comment || !canEdit || commentMutation.isPending} onClick={() => commentMutation.mutate()}>
                {commentMutation.isPending ? <Spinner /> : null}
                Submit Comment
              </button>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="panel p-5">
            <p className="section-title">Metadata</p>
            <div className="mt-4 space-y-3 text-sm text-slate-300">
              <p>Created: {formatDate(item.created_at)}</p>
              <p>Updated: {formatDate(item.updated_at)}</p>
              <p>Reporter: {item.reporter}</p>
              <p>Assigned to: {item.assigned_to || '—'}</p>
              <p>Source: {item.source_type} / {item.source_value || '—'}</p>
            </div>
          </div>
          <div className="panel p-5">
            <p className="section-title">Tags</p>
            <div className="mt-4 flex flex-wrap gap-2">
              {(item.tags || []).map((tag) => <span key={tag} className="rounded-full border border-border bg-slate-950/50 px-3 py-1 text-xs">{tag}</span>)}
            </div>
          </div>
          <div className="panel p-5">
            <p className="section-title">IOC Info</p>
            <div className="mt-4 text-sm text-slate-300">
              <p>Type: {item.ioc_type || '—'}</p>
              <p className="mt-2 break-all">Value: {item.ioc_value || '—'}</p>
              <p className="mt-2">Risk score: {item.risk_score ?? '—'}</p>
            </div>
          </div>
          <div className="panel p-5">
            <p className="section-title">Quick Actions</p>
            <div className="mt-4 grid gap-3">
              <button type="button" className="btn-secondary" onClick={() => navigate('/intelligence')}>Re-analyze</button>
              <button type="button" className="btn-secondary" onClick={() => downloadJson(`case-${item.id}.json`, item)}>Export JSON</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
