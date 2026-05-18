import { Bell, Command, LogOut, Shield } from 'lucide-react'
import { useAuthStore } from '../../store/authStore'

export default function Topbar({ onPaletteOpen, unseenCount = 0, pipeline }) {
  const user = useAuthStore((state) => state.user)
  const clearAuth = useAuthStore((state) => state.clearAuth)

  return (
    <header className="sticky top-0 z-20 border-b-2 border-cyber-cyan/30 bg-cyber-black/90 backdrop-blur relative overflow-hidden">
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGcgc3Ryb2tlPSIjMDBkNGZmIiBzdHJva2Utb3BhY2l0eT0iMC4wNSIgZmlsbD0ibm9uZSI+PHBhdGggZD0iTTAgNDBoNDBNNDAgMHY0MCIvPjwvZz48L3N2Zz4=')] opacity-30 pointer-events-none"></div>
      <div className="flex items-center justify-between gap-4 px-4 py-4 lg:px-6 relative z-10">
        <div>
          <p className="text-[10px] font-mono uppercase tracking-[0.3em] text-cyber-cyan/70 typewriter">Cyber Risk Intelligence Engine</p>
          <h1 className="mt-1 font-mono text-xl font-bold text-cyber-cyan glitch-hover">CRIE v3.0 COMMAND_CENTRE</h1>
        </div>
        <div className="flex items-center gap-3">
          <button type="button" onClick={onPaletteOpen} className="hidden items-center gap-2 rounded-none border border-cyber-cyan/40 bg-cyber-cyan/5 hover:bg-cyber-cyan/20 transition-colors px-3 py-2 text-xs font-mono text-cyber-cyan lg:inline-flex">
            <Command className="h-4 w-4" />
            [ QUICK_NAV ]
            <span className="bg-cyber-cyan/20 px-1 py-0.5 text-[10px] ml-1">CTRL+K</span>
          </button>
          <div className="hidden items-center gap-2 rounded-none border border-cyber-cyan/40 bg-cyber-black/80 px-3 py-2 text-xs font-mono md:inline-flex">
            <span className={`h-2 w-2 shadow-[0_0_8px_currentColor] ${pipeline?.isRunning ? 'bg-cyber-cyan text-cyber-cyan animate-pulse' : pipeline?.lastRun?.failed ? 'bg-cyber-red text-cyber-red' : 'bg-cyber-green text-cyber-green'}`} />
            <span className="text-cyber-cyan/80 uppercase">
              {pipeline?.isRunning ? 'PIPELINE_RUNNING' : pipeline?.lastRun ? 'PIPELINE_IDLE' : 'NO_PIPELINE_RUN'}
            </span>
          </div>
          <div className="relative rounded-none border border-cyber-cyan/40 bg-cyber-black/80 px-3 py-2">
            <Bell className="h-4 w-4 text-cyber-cyan" />
            {unseenCount ? <span className="absolute -right-1 -top-1 rounded-none border border-cyber-red bg-cyber-red/20 px-1.5 py-0.5 text-[10px] font-bold text-cyber-red shadow-[0_0_8px_rgba(255,23,68,0.5)]">{unseenCount}</span> : null}
          </div>
          <div className="hidden items-center gap-3 rounded-none border border-cyber-cyan/40 bg-cyber-black/80 px-4 py-2 md:flex">
            <Shield className="h-4 w-4 text-cyber-cyan" />
            <div>
              <p className="text-xs font-mono font-bold text-cyber-cyan">USR: {user?.username || 'UNKNOWN'}</p>
              <p className="text-[10px] font-mono uppercase tracking-widest text-cyber-cyan/50">LVL: {user?.role || 'NONE'}</p>
            </div>
          </div>
          <button type="button" className="rounded-none border border-cyber-red/50 bg-cyber-red/10 px-3 py-2 text-cyber-red hover:bg-cyber-red/20 transition-all shadow-[0_0_10px_rgba(255,23,68,0.1)]" onClick={clearAuth}>
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </header>
  )
}
