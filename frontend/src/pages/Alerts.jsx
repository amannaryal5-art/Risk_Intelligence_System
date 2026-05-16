import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getAriaAlerts, markAllAriaAlertsSeen, markAriaAlertSeen } from '../api/aria'
import RiskBadge from '../components/ui/RiskBadge'
import { formatDate } from '../lib/utils'

export default function Alerts() {
  const queryClient = useQueryClient()
  const alertsQuery = useQuery({
    queryKey: ['aria', 'alerts'],
    queryFn: getAriaAlerts,
    refetchInterval: 10000,
    refetchIntervalInBackground: true,
  })
  const seenMutation = useMutation({
    mutationFn: (id) => markAriaAlertSeen(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['aria', 'alerts'] }),
  })
  const allSeenMutation = useMutation({
    mutationFn: markAllAriaAlertsSeen,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['aria', 'alerts'] }),
  })

  return (
    <div className="space-y-6">
      <div className="flex justify-end">
        <button type="button" className="btn-secondary" onClick={() => allSeenMutation.mutate()}>Mark all seen</button>
      </div>
      <div className="grid gap-4">
        {(alertsQuery.data || []).map((alert) => (
          <div key={alert.id} className={`panel p-5 ${alert.seen ? 'opacity-80' : 'ring-1 ring-red-500/20'}`}>
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <div className="flex items-center gap-3">
                  <RiskBadge level={alert.risk_level} />
                  <p className="font-medium text-slate-100">{alert.title}</p>
                </div>
                <p className="mt-3 text-sm text-slate-300">{alert.message}</p>
                <p className="mt-3 text-xs text-slate-500">{alert.asset_value} • {formatDate(alert.created_at)}</p>
              </div>
              {!alert.seen ? <button type="button" className="btn-secondary" onClick={() => seenMutation.mutate(alert.id)}>Mark seen</button> : null}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
