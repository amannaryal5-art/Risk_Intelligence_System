import { useQuery } from '@tanstack/react-query'
import { getAriaAlerts } from '../api/aria'

export function useAlertPolling() {
  return useQuery({
    queryKey: ['aria', 'alerts'],
    queryFn: getAriaAlerts,
    refetchInterval: 60000,
  })
}
