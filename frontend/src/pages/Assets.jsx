import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import client from '../api/client'
import { addAriaAsset, deleteAriaAsset, getAriaAssets } from '../api/aria'
import Spinner from '../components/ui/Spinner'
import { formatDate } from '../lib/utils'

const BLANK = { name: '', type: 'domain', value: '', scan_interval_hours: 6 }

export default function Assets() {
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState(BLANK)

  const assetsQuery = useQuery({
    queryKey: ['aria', 'assets'],
    queryFn: getAriaAssets,
    refetchInterval: 60000,
    refetchIntervalInBackground: true,
  })

  const addMutation = useMutation({
    mutationFn: () => addAriaAsset({ ...draft, scan_interval_hours: Number(draft.scan_interval_hours) }),
    onSuccess: () => {
      setDraft(BLANK)
      queryClient.invalidateQueries({ queryKey: ['aria', 'assets'] })
      toast.success('Asset added')
    },
  })

  const scanAllMutation = useMutation({
    mutationFn: async () => (await client.post('/api/autopilot/run-task/rescan_all_assets')).data,
    onSuccess: () => toast.success('Asset rescan started'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => deleteAriaAsset(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['aria', 'assets'] }),
  })

  const scanOneMutation = useMutation({
    mutationFn: (id) => client.post(`/api/aria/assets/${id}/scan`),
    onSuccess: () => toast.success('Asset scan queued'),
  })

  const assets = assetsQuery.data || []

  return (
    <div className="space-y-6">
      <div className="panel p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="section-title">Asset Monitor</p>
          <button type="button" className="btn-primary" disabled={scanAllMutation.isPending} onClick={() => scanAllMutation.mutate()}>
            {scanAllMutation.isPending ? <Spinner /> : null}
            Scan All Assets Now
          </button>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <input className="field" placeholder="Label / name" value={draft.name} onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))} />
          <select className="field" value={draft.type} onChange={(e) => setDraft((d) => ({ ...d, type: e.target.value }))}>
            <option value="domain">domain</option>
            <option value="ip">ip</option>
            <option value="url">url</option>
            <option value="email">email</option>
          </select>
          <input className="field" placeholder="Value" value={draft.value} onChange={(e) => setDraft((d) => ({ ...d, value: e.target.value }))} />
          <button type="button" className="btn-secondary" disabled={!draft.value || addMutation.isPending} onClick={() => addMutation.mutate()}>
            {addMutation.isPending ? <Spinner /> : null}
            Add Asset
          </button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {assets.map((asset) => (
          <div key={asset.id} className="panel p-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="font-mono text-base text-slate-50">{asset.label || asset.name}</p>
                <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{asset.type} | {asset.value}</p>
              </div>
              <span className={`rounded-full px-2 py-1 text-xs font-semibold uppercase ${asset.risk_level === 'critical' ? 'bg-red-950/40 text-red-300' : asset.risk_level === 'high' ? 'bg-orange-950/40 text-orange-300' : asset.risk_level === 'medium' ? 'bg-yellow-950/40 text-yellow-300' : 'bg-emerald-950/40 text-emerald-300'}`}>
                {asset.risk_level}
              </span>
            </div>
            <div className="mt-4 space-y-2 text-sm text-slate-300">
              <p>Risk score: {asset.risk_score ?? 'unscanned'}</p>
              <p>Trend: {asset.trend}</p>
              <p>Last scanned: {formatDate(asset.last_scanned)}</p>
            </div>
            <div className="mt-4 flex gap-2">
              <button type="button" className="btn-secondary" onClick={() => scanOneMutation.mutate(asset.id)}>
                Scan Now
              </button>
              <button type="button" className="btn-secondary text-red-400" onClick={() => deleteMutation.mutate(asset.id)}>
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
