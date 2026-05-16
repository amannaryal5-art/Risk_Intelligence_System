import { motion } from 'framer-motion'
import { Activity, Bell, Bot, BriefcaseBusiness, Files, Gauge, Globe, Radar, Search, ShieldAlert, ShieldCheck, Bug, Network, Settings, FolderKanban, Zap } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import FeedDot from '../ui/FeedDot'
import { useAuthStore } from '../../store/authStore'

const navItems = [
  { to: '/', label: 'Dashboard', icon: Gauge },
  { to: '/analyze', label: 'Analyze', icon: Search },
  { to: '/threat-intel', label: 'Threat Intel', icon: Radar },
  { to: '/website-intel', label: 'Website Intel', icon: Globe },
  { to: '/malware', label: 'Malware', icon: Bug },
  { to: '/fusion-scan', label: 'Fusion Scan', icon: Activity },
  { divider: true },
  { to: '/cases', label: 'Cases', icon: FolderKanban },
  { divider: true },
  { to: '/aria', label: 'ARIA', icon: Bot },
  { to: '/assets', label: 'Assets', icon: BriefcaseBusiness },
  { to: '/alerts', label: 'Alerts', icon: Bell, badgeKey: 'alerts' },
  { to: '/autopilot', label: 'AutoPilot', icon: Zap },
  { to: '/reports', label: 'Reports', icon: Files },
  { divider: true },
  { to: '/feeds', label: 'Feed Status', icon: Network, badgeKey: 'feeds' },
]

export default function Sidebar({ unseenCount = 0, feedLive = false }) {
  const user = useAuthStore((state) => state.user)
  const clearAuth = useAuthStore((state) => state.clearAuth)

  return (
    <>
      <aside className="hidden h-screen w-72 shrink-0 border-r border-border bg-[#060a12]/90 px-4 py-6 lg:flex lg:flex-col">
        <div className="mb-8 flex items-center gap-3 px-3">
          <div className="rounded-2xl border border-cyan-700/50 bg-cyan-500/10 p-3">
            <ShieldCheck className="h-6 w-6 text-cyan-400" />
          </div>
          <div>
            <p className="font-mono text-lg font-semibold text-slate-50">CRIE v3.0</p>
            <p className="text-xs uppercase tracking-[0.25em] text-slate-500">Risk Intelligence System</p>
          </div>
        </div>

        <nav className="flex-1 space-y-2 overflow-auto">
          {navItems.map((item, index) => {
            if (item.divider) return <div key={`divider-${index}`} className="my-4 border-t border-border" />
            const Icon = item.icon
            return (
              <motion.div key={item.to} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: index * 0.03 }}>
                <NavLink
                  to={item.to}
                  className={({ isActive }) =>
                    `flex items-center justify-between rounded-xl px-3 py-2.5 text-sm transition ${
                      isActive ? 'bg-blue-600/15 text-blue-300 ring-1 ring-blue-500/30' : 'text-slate-300 hover:bg-slate-900/70'
                    }`
                  }
                >
                  <span className="flex items-center gap-3">
                    <Icon className="h-4 w-4" />
                    {item.label}
                  </span>
                  {item.badgeKey === 'alerts' && unseenCount ? <span className="rounded-full bg-red-500 px-2 py-0.5 text-[10px] font-semibold text-white">{unseenCount}</span> : null}
                  {item.badgeKey === 'feeds' ? <FeedDot status={feedLive ? 'live' : 'offline'} /> : null}
                </NavLink>
              </motion.div>
            )
          })}
          {user?.role === 'admin' ? (
            <>
              <div className="my-4 border-t border-border" />
              <NavLink
                to="/admin"
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition ${
                    isActive ? 'bg-blue-600/15 text-blue-300 ring-1 ring-blue-500/30' : 'text-slate-300 hover:bg-slate-900/70'
                  }`
                }
              >
                <Settings className="h-4 w-4" />
                Admin
              </NavLink>
            </>
          ) : null}
        </nav>

        <div className="mt-6 rounded-2xl border border-border bg-slate-950/70 p-4">
          <p className="text-sm font-medium text-slate-100">{user?.username}</p>
          <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{user?.role}</p>
          <button type="button" className="btn-secondary mt-4 w-full" onClick={clearAuth}>
            Logout
          </button>
        </div>
      </aside>

      <nav className="fixed bottom-12 left-0 right-0 z-20 border-t border-border bg-[#070b12]/96 px-2 py-2 lg:hidden">
        <div className="grid grid-cols-5 gap-1">
          {['/', '/analyze', '/threat-intel', '/cases', '/aria'].map((path) => {
            const item = navItems.find((entry) => entry.to === path) || { to: path, label: path, icon: ShieldAlert }
            const Icon = item.icon
            return (
              <NavLink key={path} to={path} className={({ isActive }) => `flex flex-col items-center rounded-xl px-2 py-2 text-[11px] ${isActive ? 'bg-blue-600/15 text-blue-300' : 'text-slate-400'}`}>
                <Icon className="h-4 w-4" />
                {item.label}
              </NavLink>
            )
          })}
        </div>
      </nav>
    </>
  )
}
