import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { getAriaAlerts, markAllAriaAlertsSeen, markAriaAlertSeen } from '../api/aria'
import RiskBadge from '../components/ui/RiskBadge'
import Spinner from '../components/ui/Spinner'
import EmptyPanel from '../components/shared/EmptyPanel'
import { formatDate } from '../lib/utils'

export default function Alerts() {
  const queryClient = useQueryClient()
  const [filter, setFilter] = useState('all')

  const alertsQuery = useQuery({
    queryKey: ['aria', 'alerts'],
    queryFn: getAriaAlerts,
    refetchInterval: 10_000,
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

  const all = alertsQuery.data || []
  const unseen = all.filter((a) => !a.seen)
  const visible =
    filter === 'unseen' ? unseen : filter === 'seen' ? all.filter((a) => a.seen) : all

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex gap-2">
          {[
            ['all', `All (${all.length})`],
            ['unseen', `Unseen (${unseen.length})`],
            ['seen', 'Seen'],
          ].map(([key, label]) => (
            <button
              key={key}
              type="button"
              className={filter === key ? 'btn-primary' : 'btn-secondary'}
              onClick={() => setFilter(key)}
            >
              {label}
            </button>
          ))}
        </div>
        <button
          type="button"
          className="btn-secondary"
          disabled={unseen.length === 0 || allSeenMutation.isPending}
          onClick={() => allSeenMutation.mutate()}
        >
          {allSeenMutation.isPending ? <Spinner /> : null}
          Mark all seen
        </button>
      </div>

      {alertsQuery.isLoading ? (
        <div className="panel flex min-h-[200px] items-center justify-center">
          <Spinner />
        </div>
      ) : visible.length === 0 ? (
        <EmptyPanel icon="🔔" title="No alerts" subtitle="All clear — no alerts match this filter." />
      ) : (
        <div className="grid gap-4">
          {visible.map((alert) => (
            <div
              key={alert.id}
              className={`panel p-5 transition ${alert.seen ? 'opacity-75' : 'ring-1 ring-red-500/20'}`}
            >
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-3">
                    <RiskBadge level={alert.risk_level} />
                    <p className="font-medium text-slate-100">{alert.title}</p>
                    {!alert.seen ? (
                      <span className="rounded-full bg-red-500/20 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-red-400">
                        new
                      </span>
                    ) : null}
                  </div>
                  <p className="mt-3 text-sm text-slate-300">{alert.message}</p>
                  <p className="mt-3 text-xs text-slate-500">
                    {alert.asset_value} • {formatDate(alert.created_at)}
                  </p>
                </div>
                {!alert.seen ? (
                  <button
                    type="button"
                    className="btn-secondary shrink-0 text-xs"
                    disabled={seenMutation.isPending}
                    onClick={() => seenMutation.mutate(alert.id)}
                  >
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
