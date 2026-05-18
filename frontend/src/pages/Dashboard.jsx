import { useNavigate } from 'react-router-dom'
import { CartesianGrid, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell } from 'recharts'
import { useAutoRefresh } from '../hooks/useAutoRefresh'
import { usePipeline } from '../hooks/usePipeline'
import RiskBadge from '../components/ui/RiskBadge'
import CaseBadge from '../components/ui/CaseBadge'
import FeedDot from '../components/ui/FeedDot'
import { formatDate, truncate } from '../lib/utils'
import { useWsStore } from '../store/wsStore'

const COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#16a34a',
}

export default function Dashboard() {
  const navigate = useNavigate()
  const { data, loading } = useAutoRefresh('/api/dashboard/stats', 30000)
  const { data: trend } = useAutoRefresh('/api/dashboard/risk-trend', 30000)
  const pipeline = usePipeline()
  const systemScan = useWsStore((state) => state.systemScan)
  const deviceScan = useWsStore((state) => state.deviceScan)
  const dismissDeviceScanBanner = useWsStore((state) => state.dismissDeviceScanBanner)

  const pieData = data?.aria_risk_distribution
    ? Object.entries(data.aria_risk_distribution)
        .map(([name, value]) => ({ name, value, color: COLORS[name] }))
        .filter((item) => item.value > 0)
    : []

  const stats = [
    ['Total Cases', data?.total_cases || 0],
    ['Critical Alerts', data?.critical_alerts || 0],
    ['Assets Monitored', data?.assets_monitored || 0],
    ['System Risk Score', Math.round(data?.system_risk_score || 0)],
    ['Last Scan', data?.last_device_scan || data?.last_system_scan ? formatDate(data?.last_device_scan || data?.last_system_scan) : 'Never'],
    ['Device Threats', data?.device_threats ?? 0],
  ]

  return (
    <div className="space-y-6">
      {deviceScan.status === 'running' ? (
        <div className="hacker-panel p-4 text-sm text-cyber-cyan font-mono animate-pulse">
          {'>'} SYSTEM_SCAN_ACTIVE :: PHASE_{deviceScan.phase?.toUpperCase() || 'INIT'} :: {deviceScan.progress}% :: {deviceScan.message}
        </div>
      ) : deviceScan.status === 'complete' && !deviceScan.dismissComplete ? (
        <div className="hacker-panel flex flex-wrap items-center justify-between gap-3 p-4 text-sm text-cyber-green font-mono">
          <span>
            {'>'} SCAN_COMPLETE :: RISK_SCORE: {deviceScan.summary?.riskScore ?? 0} :: 
            THREATS_DETECTED: {(deviceScan.summary?.connectionsFlagged || 0) + (deviceScan.summary?.processesFlagged || 0)}
          </span>
          <button type="button" className="border border-cyber-green/50 px-2 py-1 hover:bg-cyber-green/10" onClick={dismissDeviceScanBanner}>
            [ DISMISS ]
          </button>
        </div>
      ) : null}
      {systemScan.status === 'running' ? (
        <div className="hacker-panel p-4 text-sm text-cyber-cyan font-mono animate-pulse">
          {'>'} ASSET_SCAN_ACTIVE :: TARGET_{systemScan.currentAsset || 'UNKNOWN'} :: {systemScan.progress}%
        </div>
      ) : systemScan.status === 'complete' ? (
        <div className="hacker-panel p-4 text-sm text-cyber-green font-mono">
          {'>'} ASSET_SCAN_COMPLETE :: RISK_SCORE: {Math.round(systemScan.summary?.overall_risk_score || data?.asset_risk_score || 0)} :: 
          THREATS_DETECTED: {systemScan.summary?.threats_found || 0}
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        {stats.map(([label, value]) => (
          <div key={label} className="hacker-panel p-5 text-center flex flex-col items-center justify-center">
            <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-cyber-cyan/50">{label}</p>
            <p className="mt-2 font-mono text-3xl font-bold text-cyber-cyan shadow-[0_0_10px_rgba(0,212,255,0.2)] glitch-hover">{value}</p>
          </div>
        ))}
      </div>

      <div className="hacker-panel p-5">
        {pipeline.isRunning ? (
          <div className="space-y-3 font-mono">
            <div className="flex items-center justify-between text-sm text-cyber-cyan">
              <span className="typewriter">{'>'} RUNNING_JOB: {pipeline.currentTask || 'PREPARING_PIPELINE'}</span>
              <span>[{pipeline.progress}%]</span>
            </div>
            <div className="h-1 bg-cyber-cyan/20">
              <div className="h-1 bg-cyber-cyan shadow-[0_0_8px_rgba(0,212,255,0.8)] transition-all" style={{ width: `${pipeline.progress}%` }} />
            </div>
          </div>
        ) : pipeline.lastRun ? (
          <div className="flex items-center justify-between gap-4 text-sm font-mono text-cyber-cyan/80">
            <span>
              {'>'} LAST_EXECUTION: {formatDate(pipeline.lastRun.completedAt)} :: STATUS: {pipeline.lastRun.passed}/{(pipeline.lastRun.passed || 0) + (pipeline.lastRun.failed || 0)} PASSED
            </span>
            <button type="button" className="border border-cyber-cyan/50 px-3 py-1.5 hover:bg-cyber-cyan/10 hover:text-cyber-cyan transition-colors" onClick={() => navigate('/reports')}>
              [ VIEW_REPORT ]
            </button>
          </div>
        ) : (
          <p className="text-sm font-mono text-cyber-cyan/40">{'>'} NO_PIPELINE_DATA_FOUND</p>
        )}
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
        <div className="hacker-panel p-5">
          <div className="flex items-center justify-between font-mono">
            <p className="text-[12px] uppercase tracking-widest text-cyber-cyan">RISK_TREND</p>
            <span className="text-[10px] text-cyber-cyan/40">DB_SNAPSHOTS_LIVE</span>
          </div>
          <div className="mt-4 h-80">
            {!trend?.length ? (
              <div className="flex h-80 items-center justify-center font-mono text-sm text-cyber-cyan/30">
                {'>'} AWAITING_SCAN_DATA
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trend}>
                  <CartesianGrid stroke="#0d283c" strokeDasharray="3 3" />
                  <XAxis dataKey="label" stroke="#00d4ff" strokeOpacity={0.5} tick={{ fontSize: 10, fill: '#00d4ff' }} />
                  <YAxis stroke="#00d4ff" strokeOpacity={0.5} tick={{ fontSize: 10, fill: '#00d4ff' }} />
                  <Tooltip contentStyle={{ backgroundColor: '#010409', borderColor: '#00d4ff', borderRadius: '0' }} itemStyle={{ color: '#00d4ff' }} />
                  <Line type="stepAfter" dataKey="score" stroke="#00d4ff" strokeWidth={2} dot={false} activeDot={{ r: 4, fill: '#00d4ff', stroke: '#fff' }} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="hacker-panel p-5">
          <div className="flex items-center justify-between font-mono">
            <p className="text-[12px] uppercase tracking-widest text-cyber-cyan">ARIA_RISK_DISTRIBUTION</p>
            <span className="text-[10px] text-cyber-cyan/40">ASSETS: {data?.assets_monitored || 0}</span>
          </div>
          <div className="mt-4 h-80">
            {pieData.length === 0 ? (
              <div className="flex h-80 items-center justify-center font-mono text-sm text-cyber-cyan/30">{'>'} NO_ASSETS_FOUND</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} dataKey="value" innerRadius={70} outerRadius={90} paddingAngle={2} stroke="none">
                    {pieData.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#010409', borderColor: '#00d4ff', borderRadius: '0' }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <div className="hacker-panel p-5">
          <p className="text-[12px] font-mono uppercase tracking-widest text-cyber-cyan mb-4">RECENT_CASES</p>
          <div className="space-y-3">
            {(data?.recent_cases || []).map((item) => (
              <button key={item.id} type="button" className="w-full border-l-2 border-cyber-cyan bg-cyber-black/50 p-3 text-left hover:bg-cyber-cyan/10 transition-colors" onClick={() => navigate(`/cases/${item.id}`)}>
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-mono font-bold text-cyber-cyan/90">{item.title}</p>
                  <RiskBadge level={item.severity} />
                </div>
                <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-cyber-cyan/50">
                  <CaseBadge status={item.status} />
                  <span>{formatDate(item.updated_at)}</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="hacker-panel p-5">
          <p className="text-[12px] font-mono uppercase tracking-widest text-cyber-cyan mb-4">RECENT_ALERTS</p>
          <div className="space-y-3">
            {(data?.recent_alerts || []).map((item) => (
              <div key={item.id} className={`p-3 font-mono border-l-2 ${item.seen ? 'border-cyber-cyan/30 bg-cyber-black/30' : 'border-cyber-red bg-cyber-red/10'}`}>
                <div className="flex items-center justify-between gap-3">
                  <p className={`text-sm font-bold ${item.seen ? 'text-cyber-cyan/70' : 'text-cyber-red'}`}>{item.title}</p>
                  <RiskBadge level={item.severity} />
                </div>
                <p className={`mt-2 text-xs ${item.seen ? 'text-cyber-cyan/40' : 'text-cyber-red/70'}`}>{truncate(item.message, 110)}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="hacker-panel p-5">
          <p className="text-[12px] font-mono uppercase tracking-widest text-cyber-cyan mb-4">FEED_STATUS</p>
          <div className="space-y-3">
            {(data?.feed_status || []).map((feed) => (
              <div key={feed.name} className="flex items-center justify-between border border-cyber-cyan/20 bg-cyber-cyan/5 px-3 py-2 text-xs font-mono">
                <span className="text-cyber-cyan/80">{feed.display_name}</span>
                <div className="flex items-center gap-2">
                  <FeedDot status={feed.auth_valid ? 'live' : feed.reachable ? 'degraded' : 'offline'} />
                  <span className={feed.auth_valid ? 'text-cyber-green' : feed.reachable ? 'text-yellow-500' : 'text-cyber-red'}>
                    {feed.warning || (feed.auth_valid ? 'LIVE' : feed.reachable ? 'DEGRADED' : 'OFFLINE')}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {loading ? <div className="hacker-panel p-5 text-sm font-mono text-cyber-cyan/50 animate-pulse">{'>'} ESTABLISHING_UPLINK...</div> : null}
    </div>
  )
}
