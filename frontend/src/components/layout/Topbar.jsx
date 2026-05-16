import { Bell, Command, LogOut, Shield } from 'lucide-react'
import { useAuthStore } from '../../store/authStore'

export default function Topbar({ onPaletteOpen, unseenCount = 0 }) {
  const user = useAuthStore((state) => state.user)
  const clearAuth = useAuthStore((state) => state.clearAuth)

  return (
    <header className="sticky top-0 z-20 border-b border-border bg-[#080c14]/85 backdrop-blur">
      <div className="flex items-center justify-between gap-4 px-4 py-4 lg:px-6">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-cyan-400">Cyber Risk Intelligence Engine</p>
          <h1 className="mt-1 font-mono text-xl font-semibold text-slate-50">CRIE v3.0 Command Centre</h1>
        </div>
        <div className="flex items-center gap-3">
          <button type="button" onClick={onPaletteOpen} className="hidden items-center gap-2 rounded-xl border border-border bg-slate-950/80 px-3 py-2 text-sm text-slate-300 lg:inline-flex">
            <Command className="h-4 w-4" />
            Quick Nav
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs">Ctrl/Cmd+K</span>
          </button>
          <div className="relative rounded-xl border border-border bg-slate-950/80 px-3 py-2">
            <Bell className="h-4 w-4 text-slate-300" />
            {unseenCount ? <span className="absolute -right-1 -top-1 rounded-full bg-red-500 px-1.5 py-0.5 text-[10px] font-semibold text-white">{unseenCount}</span> : null}
          </div>
          <div className="hidden items-center gap-3 rounded-xl border border-border bg-slate-950/80 px-4 py-2 md:flex">
            <Shield className="h-4 w-4 text-cyan-400" />
            <div>
              <p className="text-sm font-medium text-slate-100">{user?.username || 'Unknown user'}</p>
              <p className="text-xs uppercase tracking-wide text-slate-500">{user?.role || 'no role'}</p>
            </div>
          </div>
          <button type="button" className="btn-secondary px-3 py-2" onClick={clearAuth}>
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </header>
  )
}
