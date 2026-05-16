import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, RefreshCw, Trash2 } from 'lucide-react'
import toast from 'react-hot-toast'
import {
  addAriaAsset,
  deleteAriaAsset,
  getAriaAssetHistory,
  getAriaAssetSummary,
  getAriaAssets,
  scanAriaAsset,
} from '../api/aria'
import RiskBadge from '../components/ui/RiskBadge'
import Spinner from '../components/ui/Spinner'
import EmptyPanel from '../components/shared/EmptyPanel'
import { formatDate } from '../lib/utils'
import { useAuthStore } from '../store/authStore'

const BLANK = { name: '', type: 'domain', value: '', scan_interval_hours: 6 }

export default function Assets() {
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const canEdit = user?.role !== 'viewer'
  const [draft, setDraft] = useState(BLANK)
  const [expanded, setExpanded] = useState(null)

  const assetsQuery = useQuery({
    queryKey: ['aria', 'assets'],
    queryFn: getAriaAssets,
    refetchInterval: 15_000,
    refetchIntervalInBackground: true,
  })

  const addMutation = useMutation({
    mutationFn: () =>
      addAriaAsset({ ...draft, scan_interval_hours: Number(draft.scan_interval_hours) }),
    onSuccess: () => {
      setDraft(BLANK)
      queryClient.invalidateQueries({ queryKey: ['aria', 'assets'] })
      toast.success('Asset added')
    },
    onError: (err) => toast.error(err.response?.data?.detail || 'Failed to add asset'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => deleteAriaAsset(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['aria', 'assets'] })
      toast.success('Asset removed')
    },
    onError: (err) => toast.error(err.response?.data?.detail || 'Failed to delete asset'),
  })

  const scanMutation = useMutation({
    mutationFn: (id) => scanAriaAsset(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['aria', 'assets'] })
      toast.success('Scan queued')
    },
    onError: (err) => toast.error(err.response?.data?.detail || 'Scan failed'),
  })

  const assets = assetsQuery.data || []

  return (
    <div className="space-y-6">
      {canEdit ? (
        <div className="panel p-5">
          <p className="section-title mb-4">Register New Asset</p>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <input
              className="field"
              placeholder="Label / name"
              value={draft.name}
              onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
            />
            <select
              className="field"
              value={draft.type}
              onChange={(e) => setDraft((d) => ({ ...d, type: e.target.value }))}
            >
              <option value="domain">domain</option>
              <option value="ip">ip</option>
              <option value="url">url</option>
              <option value="email">email</option>
            </select>
            <input
              className="field"
              placeholder="Value (e.g. example.com)"
              value={draft.value}
              onChange={(e) => setDraft((d) => ({ ...d, value: e.target.value }))}
            />
            <input
              className="field"
              type="number"
              min="1"
              max="168"
              title="Scan interval (hours)"
              placeholder="Interval (hrs)"
              value={draft.scan_interval_hours}
              onChange={(e) => setDraft((d) => ({ ...d, scan_interval_hours: e.target.value }))}
            />
          </div>
          <button
            type="button"
            className="btn-primary mt-4"
            disabled={!draft.value || addMutation.isPending}
            onClick={() => addMutation.mutate()}
          >
            {addMutation.isPending ? <Spinner /> : <Plus className="h-4 w-4" />}
            Add Asset
          </button>
        </div>
      ) : null}

      {assetsQuery.isLoading ? (
        <div className="panel flex min-h-[200px] items-center justify-center">
          <Spinner />
        </div>
      ) : assets.length === 0 ? (
        <EmptyPanel
          icon="🛡️"
          title="No assets registered"
          subtitle="Add a domain, IP, URL, or email above to start monitoring."
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {assets.map((asset) => (
            <AssetCard
              key={asset.id}
              asset={asset}
              expanded={expanded === asset.id}
              canEdit={canEdit}
              onToggle={() => setExpanded((v) => (v === asset.id ? null : asset.id))}
              onScan={() => scanMutation.mutate(asset.id)}
              onDelete={() => {
                if (window.confirm(`Delete "${asset.name || asset.value}"?`)) {
                  deleteMutation.mutate(asset.id)
                }
              }}
              isScanPending={scanMutation.isPending && scanMutation.variables === asset.id}
              isDeletePending={deleteMutation.isPending && deleteMutation.variables === asset.id}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function AssetCard({
  asset,
  expanded,
  canEdit,
  onToggle,
  onScan,
  onDelete,
  isScanPending,
  isDeletePending,
}) {
  const historyQuery = useQuery({
    queryKey: ['aria', 'history', asset.id],
    queryFn: () => getAriaAssetHistory(asset.id),
    enabled: expanded,
  })
  const summaryQuery = useQuery({
    queryKey: ['aria', 'summary', asset.id],
    queryFn: () => getAriaAssetSummary(asset.id),
    enabled: expanded,
  })

  return (
    <div className="panel p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-mono text-base text-slate-50">{asset.name || asset.value}</p>
          <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">
            {asset.type} • {asset.value}
          </p>
        </div>
        <RiskBadge level={asset.last_risk_level || 'unknown'} />
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2 text-xs text-slate-400">
        <span>Score: {asset.last_risk_score ?? '—'}</span>
        <span>Interval: {asset.scan_interval_hours}h</span>
        <span className="col-span-2">
          Last scan: {formatDate(asset.last_scanned_at || asset.last_scanned)}
        </span>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        <button type="button" className="btn-secondary text-xs" onClick={onToggle}>
          {expanded ? 'Hide history' : 'View history'}
        </button>
        {canEdit ? (
          <>
            <button
              type="button"
              className="btn-secondary text-xs"
              disabled={isScanPending}
              onClick={onScan}
            >
              {isScanPending ? <Spinner /> : <RefreshCw className="h-3 w-3" />}
              Scan now
            </button>
            <button
              type="button"
              className="btn-secondary text-xs text-red-400 hover:border-red-700"
              disabled={isDeletePending}
              onClick={onDelete}
            >
              {isDeletePending ? <Spinner /> : <Trash2 className="h-3 w-3" />}
              Delete
            </button>
          </>
        ) : null}
      </div>

      {expanded ? (
        <div className="mt-4 space-y-3 border-t border-border pt-4">
          {summaryQuery.data?.summary ? (
            <p className="text-sm text-slate-300">{summaryQuery.data.summary}</p>
          ) : null}
          <p className="section-title text-xs">Scan history ({historyQuery.data?.length || 0})</p>
          {historyQuery.isLoading ? (
            <Spinner />
          ) : (historyQuery.data || []).length === 0 ? (
            <p className="text-xs text-slate-500">No scan history yet.</p>
          ) : (
            <div className="max-h-60 space-y-2 overflow-y-auto">
              {(historyQuery.data || []).slice(0, 15).map((entry, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between rounded-lg border border-border bg-slate-950/50 px-3 py-2 text-xs"
                >
                  <span className="text-slate-400">{formatDate(entry.scanned_at)}</span>
                  <RiskBadge level={entry.risk_level || 'unknown'} />
                  <span className="text-slate-300">{entry.risk_score ?? '—'}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : null}
    </div>
  )
}
