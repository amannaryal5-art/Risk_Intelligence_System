import { motion } from 'framer-motion'
import { Bell, Bot, BriefcaseBusiness, Files, Gauge, HardDrive, Search, ShieldAlert, ShieldCheck, Network, Settings, FolderKanban, Zap } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import FeedDot from '../ui/FeedDot'
import { useAuthStore } from '../../store/authStore'

const navItems = [
  { to: '/', label: 'Dashboard', icon: Gauge },
  { to: '/intelligence', label: 'Intelligence', icon: Search },
  { to: '/device', label: 'Device Scan', icon: HardDrive },
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
      <aside className="hidden h-screen w-72 shrink-0 border-r border-cyber-cyan/20 bg-[#020408]/95 px-4 py-6 lg:flex lg:flex-col relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none opacity-20 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGNpcmNsZSBjeD0iMiIgY3k9IjIiIHI9IjEiIGZpbGw9IiMwMGQ0ZmYiLz48L3N2Zz4=')]"></div>
        <div className="mb-8 flex items-center gap-3 px-3 relative z-10">
          <div className="relative">
            <div className="absolute inset-0 animate-ping opacity-20 rounded-none border border-cyber-cyan"></div>
            <div className="rounded-none border-2 border-cyber-cyan bg-cyber-cyan/10 p-3 shadow-[0_0_15px_rgba(0,212,255,0.4)]">
              <ShieldCheck className="h-6 w-6 text-cyber-cyan" />
            </div>
          </div>
          <div>
            <p className="font-mono text-lg font-bold text-cyber-cyan glitch-hover">CRIE v3.0</p>
            <p className="text-[10px] uppercase tracking-[0.3em] text-cyber-cyan/60">Risk Intel System</p>
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
                    `group flex items-center justify-between px-3 py-2.5 text-sm font-mono transition-all ${
                      isActive ? 'border-l-2 border-cyber-cyan bg-cyber-cyan/10 text-cyber-cyan shadow-[inset_4px_0_10px_rgba(0,212,255,0.1)]' : 'border-l-2 border-transparent text-slate-400 hover:border-cyber-cyan/50 hover:bg-cyber-cyan/5 hover:text-cyber-cyan/80'
                    }`
                  }
                >
                  <span className="flex items-center gap-3 relative">
                    <Icon className="h-4 w-4" />
                    <span className="group-hover:translate-x-1 transition-transform">
                      {item.label}
                    </span>
                  </span>
                  {item.badgeKey === 'alerts' && unseenCount ? <span className="rounded-none border border-cyber-red bg-cyber-red/20 px-2 py-0.5 text-[10px] font-bold text-cyber-red shadow-[0_0_8px_rgba(255,23,68,0.5)]">{unseenCount}</span> : null}
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
                  `group flex items-center gap-3 px-3 py-2.5 text-sm font-mono transition-all ${
                    isActive ? 'border-l-2 border-cyber-purple bg-cyber-purple/10 text-cyber-purple shadow-[inset_4px_0_10px_rgba(179,0,255,0.1)]' : 'border-l-2 border-transparent text-slate-400 hover:border-cyber-purple/50 hover:bg-cyber-purple/5 hover:text-cyber-purple/80'
                  }`
                }
              >
                <Settings className="h-4 w-4" />
                Admin
              </NavLink>
            </>
          ) : null}
        </nav>

        <div className="mt-6 hacker-panel p-4 z-10">
          <div className="flex items-center gap-2 mb-2">
            <span className="w-2 h-2 bg-cyber-green animate-pulse inline-block"></span>
            <p className="text-sm font-mono font-bold text-cyber-green glitch-hover">SYS_USER: {user?.username}</p>
          </div>
          <p className="mt-1 text-[10px] font-mono uppercase tracking-widest text-cyber-cyan/50">AUTH_LEVEL: {user?.role}</p>
          <button type="button" className="mt-4 w-full border border-cyber-red/50 bg-cyber-red/10 px-4 py-2 text-xs font-mono text-cyber-red hover:bg-cyber-red/20 transition-all shadow-[0_0_10px_rgba(255,23,68,0.1)]" onClick={clearAuth}>
            [ DISCONNECT ]
          </button>
        </div>
      </aside>

      <nav className="fixed bottom-12 left-0 right-0 z-20 border-t border-border bg-[#070b12]/96 px-2 py-2 lg:hidden">
        <div className="grid grid-cols-5 gap-1">
          {['/', '/intelligence', '/cases', '/aria', '/alerts'].map((path) => {
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
