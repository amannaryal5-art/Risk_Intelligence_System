import { useEffect, useRef, useState } from 'react'
import client from '../api/client'

export function useAutoRefresh(endpoint, intervalMs = 30000) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const timerRef = useRef(null)

  useEffect(() => {
    let active = true

    const load = async () => {
      if (document.hidden) return
      try {
        const response = await client.get(endpoint)
        if (!active) return
        setData(response.data)
        setError(null)
      } catch (err) {
        if (!active) return
        setError(err)
      } finally {
        if (active) setLoading(false)
      }
    }

    load()
    timerRef.current = window.setInterval(load, intervalMs)

    const onVisibility = () => {
      if (!document.hidden) load()
    }
    document.addEventListener('visibilitychange', onVisibility)

    return () => {
      active = false
      document.removeEventListener('visibilitychange', onVisibility)
      if (timerRef.current) window.clearInterval(timerRef.current)
    }
  }, [endpoint, intervalMs])

  return { data, loading, error }
}
