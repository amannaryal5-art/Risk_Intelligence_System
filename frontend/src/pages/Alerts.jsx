import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { getAriaAlerts, markAllAriaAlertsSeen, markAriaAlertSeen } from '../api/aria'
import RiskBadge from '../components/ui/RiskBadge'
import Spinner from '../components/ui/Spinner'
import EmptyPanel from '../components/shared/EmptyPanel'
import { formatDate } from '../lib/utils'
import { useWsStore } from '../store/wsStore'

export default function Alerts() {
  const queryClient = useQueryClient()
  const liveAlerts = useWsStore((state) => state.liveAlerts)
  const [tab, setTab] = useState('all')
  const [severity, setSeverity] = useState('ALL')

  const alertsQuery = useQuery({
    queryKey: ['aria', 'alerts'],
    queryFn: getAriaAlerts,
    refetchInterval: 15000,
    refetchIntervalInBackground: true,
  })

  const seenMutation = useMutation({
    mutationFn: (id) => markAriaAlertSeen(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['aria', 'alerts'] }),
    onError: () => toast.error('Failed to mark alert seen'),
  })

  const allSeenMutation = useMutation({
    mutationFn: markAllAriaAlertsSeen,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['aria', 'alerts'] })
      toast.success('All alerts marked as seen')
    },
    onError: () => toast.error('Failed to mark all seen'),
  })

  const merged = useMemo(() => {
    const stored = alertsQuery.data || []
    const mappedLive = liveAlerts.map((alert, index) => ({
      id: `live-${index}-${alert.alert_id}`,
      title: alert.message,
      message: alert.message,
      severity: alert.severity,
      risk_level: alert.severity,
      asset_value: alert.asset,
      created_at: new Date().toISOString(),
      seen: false,
    }))
    const dedup = [...mappedLive, ...stored]
    return dedup.filter((item, index, array) => index === array.findIndex((other) => String(other.id) === String(item.id) || (other.message === item.message && other.asset_value === item.asset_value)))
  }, [alertsQuery.data, liveAlerts])

  const filtered = merged.filter((alert) => {
    if (tab === 'unseen' && alert.seen) return false
    if (tab === 'seen' && !alert.seen) return false
    if (severity !== 'ALL' && String(alert.severity || alert.risk_level || '').toUpperCase() !== severity) return false
    return true
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex gap-2">
          {[
            ['all', `All (${merged.length})`],
            ['unseen', `Unseen (${merged.filter((a) => !a.seen).length})`],
            ['seen', 'Seen'],
          ].map(([key, label]) => (
            <button key={key} type="button" className={tab === key ? 'btn-primary' : 'btn-secondary'} onClick={() => setTab(key)}>
              {label}
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((item) => (
            <button key={item} type="button" className={severity === item ? 'btn-primary' : 'btn-secondary'} onClick={() => setSeverity(item)}>
              {item}
            </button>
          ))}
          <button type="button" className="btn-secondary" disabled={allSeenMutation.isPending} onClick={() => allSeenMutation.mutate()}>
            {allSeenMutation.isPending ? <Spinner /> : null}
            Mark all seen
          </button>
        </div>
      </div>

      {alertsQuery.isLoading ? (
        <div className="panel flex min-h-[200px] items-center justify-center"><Spinner /></div>
      ) : filtered.length === 0 ? (
        <EmptyPanel icon="Alerts" title="No alerts" subtitle="Run AutoPilot to scan assets and generate live alerts." />
      ) : (
        <div className="grid gap-4">
          {filtered.map((alert) => (
            <div key={alert.id} className={`panel p-5 transition ${alert.seen ? 'opacity-75' : 'ring-1 ring-red-500/20'}`}>
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-3">
                    <RiskBadge level={alert.severity || alert.risk_level} />
                    <p className="font-medium text-slate-100">{alert.title}</p>
                  </div>
                  <p className="mt-3 text-sm text-slate-300">{alert.message}</p>
                  <p className="mt-3 text-xs text-slate-500">{alert.asset_value} | {formatDate(alert.created_at)}</p>
                </div>
                {!alert.seen && !String(alert.id).startsWith('live-') ? (
                  <button type="button" className="btn-secondary shrink-0 text-xs" disabled={seenMutation.isPending} onClick={() => seenMutation.mutate(alert.id)}>
                    Mark seen
                  </button>
                ) : null}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
