import { useEffect, useState } from 'react'

export function useThrottle(value, delay = 300) {
  const [throttled, setThrottled] = useState(value)

  useEffect(() => {
    const id = setTimeout(() => setThrottled(value), delay)
    return () => clearTimeout(id)
  }, [value, delay])

  return throttled
}
