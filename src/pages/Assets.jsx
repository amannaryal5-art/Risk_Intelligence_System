import { useQuery } from '@tanstack/react-query'
import { getAriaAssets, getAriaAssetHistory, getAriaAssetSummary } from '../api/aria'
import RiskBadge from '../components/ui/RiskBadge'
import Spinner from '../components/ui/Spinner'
import { formatDate } from '../lib/utils'

export default function Assets() {
  const assetsQuery = useQuery({
    queryKey: ['aria', 'assets'],
    queryFn: getAriaAssets,
    refetchInterval: 15000,
    refetchIntervalInBackground: true,
  })

  if (assetsQuery.isLoading) return <div className="panel p-6"><Spinner /></div>

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      {(assetsQuery.data || []).map((asset) => (
        <AssetCard key={asset.id} asset={asset} />
      ))}
    </div>
  )
}

function AssetCard({ asset }) {
  const historyQuery = useQuery({ queryKey: ['aria', 'history', asset.id], queryFn: () => getAriaAssetHistory(asset.id) })
  const summaryQuery = useQuery({ queryKey: ['aria', 'summary', asset.id], queryFn: () => getAriaAssetSummary(asset.id) })

  return (
    <div className="panel p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="font-mono text-lg text-slate-50">{asset.name || asset.value}</p>
          <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{asset.type} • {asset.value}</p>
        </div>
        <RiskBadge level={asset.last_risk_level || 'unknown'} />
      </div>
      <p className="mt-4 text-sm text-slate-300">{summaryQuery.data?.summary || asset.last_summary || 'No summary available yet.'}</p>
      <div className="mt-4 space-y-2 text-sm text-slate-400">
        <p>Score: {asset.last_risk_score ?? '—'}</p>
        <p>Last scanned: {formatDate(asset.last_scanned_at || asset.last_scanned)}</p>
        <p>History entries: {historyQuery.data?.length || 0}</p>
      </div>
    </div>
  )
}
