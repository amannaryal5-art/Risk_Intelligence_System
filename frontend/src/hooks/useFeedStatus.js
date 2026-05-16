import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getFeedsStatus } from '../api/feeds'
import { getWsUrl } from '../lib/utils'
import { useWsStore } from '../store/wsStore'

export function useFeedStatus() {
  const setFeedStatus = useWsStore((state) => state.setFeedStatus)
  const setConnected = useWsStore((state) => state.setConnected)

  const query = useQuery({
    queryKey: ['feeds', 'status'],
    queryFn: getFeedsStatus,
    refetchInterval: 30000,
    refetchIntervalInBackground: true,
  })

  useEffect(() => {
    if (query.data) setFeedStatus(query.data)
  }, [query.data, setFeedStatus])

  useEffect(() => {
    let socket
    let stopped = false
    let retry = 1000

    const connect = () => {
      socket = new WebSocket(getWsUrl('/api/v1/ws/feeds/status'))

      socket.onopen = () => {
        retry = 1000
        setConnected(true)
      }

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data)
          if (payload?.data) setFeedStatus(payload.data)
        } catch {
          return
        }
      }

      socket.onerror = () => {
        socket?.close()
      }

      socket.onclose = () => {
        setConnected(false)
        if (stopped) return
        const delay = retry
        retry = Math.min(retry * 2, 8000)
        window.setTimeout(connect, delay)
      }
    }

    connect()

    return () => {
      stopped = true
      setConnected(false)
      socket?.close()
    }
  }, [setConnected, setFeedStatus])

  return query
}
