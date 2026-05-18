import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getFeedsStatus } from '../api/feeds'
import { getWsUrl } from '../lib/utils'
import { useWsStore } from '../store/wsStore'

export function useFeedStatus() {
  const setFeedStatus = useWsStore((state) => state.setFeedStatus)
  const setConnected = useWsStore((state) => state.setConnected)
  const handlePipelineEvent = useWsStore((state) => state.handlePipelineEvent)
  const setPipelineSnapshot = useWsStore((state) => state.setPipelineSnapshot)
  const pushLiveAlert = useWsStore((state) => state.pushLiveAlert)
  const handleSystemScanEvent = useWsStore((state) => state.handleSystemScanEvent)
  const handleDeviceScanEvent = useWsStore((state) => state.handleDeviceScanEvent)

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
          if (payload?.type === 'feed_status' && payload?.data) setFeedStatus(payload.data)
          if (payload?.type === 'pipeline_snapshot' && payload?.data) setPipelineSnapshot(payload.data)
          if (['pipeline_start', 'task_start', 'task_complete', 'pipeline_done'].includes(payload?.type)) {
            handlePipelineEvent(payload)
          }
          if (payload?.type === 'new_alert') pushLiveAlert(payload)
          if (['system_scan_progress', 'system_scan_complete'].includes(payload?.type)) handleSystemScanEvent(payload)
          if (['device_scan_started', 'device_scan_progress', 'device_scan_complete'].includes(payload?.type)) {
            handleDeviceScanEvent(payload)
          }
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
  }, [handleDeviceScanEvent, handlePipelineEvent, handleSystemScanEvent, pushLiveAlert, setConnected, setFeedStatus, setPipelineSnapshot])

  return query
}
