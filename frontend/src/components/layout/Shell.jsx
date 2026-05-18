import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import client from '../../api/client'
import Sidebar from './Sidebar'
import Topbar from './Topbar'
import FeedStatusBar from './FeedStatusBar'
import { useAlertPolling } from '../../hooks/useAlertPolling'
import { useFeedStatus } from '../../hooks/useFeedStatus'
import { usePipeline } from '../../hooks/usePipeline'
import { useWsStore } from '../../store/wsStore'

const commandItems = [
  ['Dashboard', '/'],
  ['Intelligence', '/intelligence'],
  ['Device Scan', '/device'],
  ['Cases', '/cases'],
  ['ARIA', '/aria'],
  ['Assets', '/assets'],
  ['Alerts', '/alerts'],
  ['Reports', '/reports'],
  ['Feed Status', '/feeds'],
  ['Admin', '/admin'],
]

export default function Shell({ children, userRole = 'viewer' }) {
  const navigate = useNavigate()
  useFeedStatus()
  const alertsQuery = useAlertPolling()
  const feedStatus = useWsStore((state) => state.feedStatus)
  const connected = useWsStore((state) => state.connected)
  const setSystemScanSnapshot = useWsStore((state) => state.setSystemScanSnapshot)
  const pipeline = usePipeline()
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [query, setQuery] = useState('')

  const sessionQuery = useQuery({
    queryKey: ['intelligence', 'last-session', 'shell'],
    queryFn: async () => (await client.get('/api/intelligence/last-session')).data,
    retry: false,
  })

  useEffect(() => {
    if (sessionQuery.data) setSystemScanSnapshot(sessionQuery.data)
  }, [sessionQuery.data, setSystemScanSnapshot])

  useEffect(() => {
    const onKey = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setPaletteOpen((value) => !value)
      }
      if (event.key === 'Escape') setPaletteOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const items = useMemo(() => {
    const base = userRole === 'admin' ? commandItems : commandItems.filter((item) => item[1] !== '/admin')
    return base.filter(([label]) => label.toLowerCase().includes(query.toLowerCase()))
  }, [query, userRole])

  const liveCount = feedStatus?.summary?.auth_valid || 0
  const unseenCount = (alertsQuery.data || []).filter((item) => !item.seen).length

  return (
    <div className="flex min-h-screen bg-transparent text-slate-50">
      <Sidebar unseenCount={unseenCount} feedLive={connected && liveCount > 0} />
      <div className="flex min-h-screen flex-1 flex-col pb-24 lg:pb-12">
        <Topbar unseenCount={unseenCount} pipeline={pipeline} onPaletteOpen={() => setPaletteOpen(true)} />
        <main className="grid-lines flex-1 px-4 py-6 lg:px-6">{children}</main>
      </div>
      <FeedStatusBar />

      {paletteOpen ? (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-20" onClick={() => setPaletteOpen(false)}>
          <div className="hacker-panel w-full max-w-2xl p-4 shadow-glow" onClick={(event) => event.stopPropagation()}>
            <div className="flex items-center gap-2 border-b border-cyber-cyan/30 pb-2 mb-4">
              <span className="text-cyber-cyan font-mono">{'>_'}</span>
              <input autoFocus className="w-full bg-transparent text-sm text-cyber-cyan outline-none font-mono placeholder-cyber-cyan/50" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Jump to a page or execute command…" />
            </div>
            <div className="mt-4 space-y-2">
              {items.map(([label, path]) => (
                <button
                  key={path}
                  type="button"
                  className="flex w-full items-center justify-between border-l-2 border-transparent bg-cyber-black/70 px-4 py-3 text-left text-sm text-cyber-cyan/70 hover:border-cyber-cyan hover:bg-cyber-cyan/10 hover:text-cyber-cyan glitch-hover"
                  onClick={() => {
                    navigate(path)
                    setPaletteOpen(false)
                    setQuery('')
                  }}
                >
                  <span>{label}</span>
                  <span className="text-xs text-slate-500">{path}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}
