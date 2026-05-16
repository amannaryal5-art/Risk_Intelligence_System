import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import Sidebar from './Sidebar'
import Topbar from './Topbar'
import FeedStatusBar from './FeedStatusBar'
import { useAlertPolling } from '../../hooks/useAlertPolling'
import { useFeedStatus } from '../../hooks/useFeedStatus'
import { useWsStore } from '../../store/wsStore'

const commandItems = [
  ['Dashboard', '/'],
  ['AutoPilot', '/autopilot'],
  ['Analyze', '/analyze'],
  ['Threat Intel', '/threat-intel'],
  ['Website Intel', '/website-intel'],
  ['Malware', '/malware'],
  ['Fusion Scan', '/fusion-scan'],
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
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [query, setQuery] = useState('')

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
        <Topbar unseenCount={unseenCount} onPaletteOpen={() => setPaletteOpen(true)} />
        <main className="grid-lines flex-1 px-4 py-6 lg:px-6">{children}</main>
      </div>
      <FeedStatusBar />

      {paletteOpen ? (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-20" onClick={() => setPaletteOpen(false)}>
          <div className="panel-elevated w-full max-w-2xl p-4" onClick={(event) => event.stopPropagation()}>
            <input autoFocus className="field" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Jump to a page…" />
            <div className="mt-4 space-y-2">
              {items.map(([label, path]) => (
                <button
                  key={path}
                  type="button"
                  className="flex w-full items-center justify-between rounded-xl border border-border bg-slate-950/70 px-4 py-3 text-left text-sm text-slate-200 hover:border-blue-500/40 hover:bg-slate-900"
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
