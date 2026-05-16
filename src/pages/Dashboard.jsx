import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'
import { getHealth } from '../api/auth'
import { listCases } from '../api/cases'
import { getAriaStats } from '../api/aria'
import { useAlertPolling } from '../hooks/useAlertPolling'
import { useWsStore } from '../store/wsStore'
import RiskBadge from '../components/ui/RiskBadge'
import CaseBadge from '../components/ui/CaseBadge'
import FeedDot from '../components/ui/FeedDot'
import { normalizeRiskLevel, readHistory, truncate, formatDate } from '../lib/utils'

export default function Dashboard() {
  const navigate = useNavigate()
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    refetchInterval: 30000,
    refetchIntervalInBackground: true,
  })
  const { data: caseData } = useQuery({
    queryKey: ['cases', 'recent'],
    queryFn: () => listCases({ limit: 5 }),
    refetchInterval: 20000,
    refetchIntervalInBackground: true,
  })
  const { data: ariaStats } = useQuery({
    queryKey: ['aria', 'stats'],
    queryFn: getAriaStats,
    refetchInterval: 20000,
    refetchIntervalInBackground: true,
  })
  const alertsQuery = useAlertPolling()
  const feedStatus = useWsStore((state) => state.feedStatus)

  const analyses = readHistory('crie-analysis-history')
  const websiteHistory = readHistory('crie-website-history')
  const trendData = analyses.slice(0, 20).reverse().map((item, index) => ({ index: index + 1, score: item.score || item.risk_score || 0 }))
  const pieData = useMemo(() => {
    if (!ariaStats) return []
    return [
      ['Critical', ariaStats.critical, '#dc2626'],
      ['High', ariaStats.high, '#ea580c'],
      ['Medium', ariaStats.medium, '#d97706'],
      ['Low', ariaStats.low, '#16a34a'],
      ['Clean', ariaStats.clean, '#059669'],
      ['Unknown', ariaStats.unknown, '#64748b'],
    ].filter((item) => item[1] > 0).map(([name, value, color]) => ({ name, value, color }))
  }, [ariaStats])

  const stats = [
    ['Total Cases', caseData?.count || 0],
    ['Critical Alerts', (alertsQuery.data || []).filter((item) => normalizeRiskLevel(item.risk_level) === 'critical').length],
    ['Assets Monitored', ariaStats?.total || 0],
    ['Live Feed Count', feedStatus?.summary?.auth_valid || 0],
  ]

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {stats.map(([label, value]) => (
          <div key={label} className="panel p-5">
            <p className="section-title">{label}</p>
            <p className="mt-4 font-mono text-3xl font-semibold text-slate-50">{value}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
        <div className="panel p-5">
          <div className="flex items-center justify-between">
            <p className="section-title">Risk Trend</p>
            <span className="text-xs text-slate-500">Last 20 analyses</span>
          </div>
          <div className="mt-4 h-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendData}>
                <CartesianGrid stroke="#1e2a3a" strokeDasharray="3 3" />
                <XAxis dataKey="index" stroke="#64748b" />
                <YAxis stroke="#64748b" />
                <Tooltip />
                <Line type="monotone" dataKey="score" stroke="#06b6d4" strokeWidth={2.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel p-5">
          <div className="flex items-center justify-between">
            <p className="section-title">ARIA Risk Distribution</p>
            <span className="text-xs text-slate-500">{ariaStats?.total || 0} assets</span>
          </div>
          <div className="mt-4 h-80">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={pieData} dataKey="value" innerRadius={60} outerRadius={90} paddingAngle={3}>
                  {pieData.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <div className="panel p-5">
          <p className="section-title">Recent Cases</p>
          <div className="mt-4 space-y-3">
            {(caseData?.results || []).map((item) => (
              <button key={item.id} type="button" className="w-full rounded-xl border border-border bg-slate-950/50 p-4 text-left" onClick={() => navigate(`/cases/${item.id}`)}>
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-medium text-slate-100">{item.title}</p>
                  <RiskBadge level={item.severity} />
                </div>
                <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
                  <CaseBadge status={item.status} />
                  <span>{formatDate(item.updated_at)}</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="panel p-5">
          <p className="section-title">Recent Alerts</p>
          <div className="mt-4 space-y-3">
            {(alertsQuery.data || []).slice(0, 5).map((item) => (
              <div key={item.id} className={`rounded-xl border p-4 ${item.seen ? 'border-border bg-slate-950/40' : 'border-red-900/50 bg-red-950/20'}`}>
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-medium text-slate-100">{item.title}</p>
                  <RiskBadge level={item.risk_level} />
                </div>
                <p className="mt-2 text-sm text-slate-400">{truncate(item.message, 110)}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="panel p-5">
          <p className="section-title">Feed Status</p>
          <div className="mt-4 space-y-3">
            {(feedStatus?.feeds || []).map((feed) => (
              <div key={feed.name} className="flex items-center justify-between rounded-xl border border-border bg-slate-950/50 px-4 py-3 text-sm">
                <span>{feed.display_name}</span>
                <div className="flex items-center gap-2 text-slate-400">
                  <FeedDot status={feed.auth_valid ? 'live' : feed.reachable ? 'degraded' : 'offline'} />
                  <span>{feed.auth_valid ? 'live' : feed.reachable ? 'auth issue' : 'offline'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-4">
        {[
          ['Analyze Text', '/analyze'],
          ['Check Website', '/website-intel'],
          ['Scan IOC', '/threat-intel'],
          ['Chat with ARIA', '/aria'],
        ].map(([label, path]) => (
          <button key={path} type="button" className="btn-secondary w-full py-4" onClick={() => navigate(path)}>
            {label}
          </button>
        ))}
      </div>

      {websiteHistory.length ? (
        <div className="panel p-5">
          <p className="section-title">Recent Website Scans</p>
          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {websiteHistory.slice(0, 6).map((item, index) => (
              <div key={`${item.input}-${index}`} className="rounded-xl border border-border bg-slate-950/50 p-4">
                <p className="font-mono text-sm text-slate-100">{item.domain || item.input}</p>
                <p className="mt-2 text-sm text-slate-400">{item.summary}</p>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      <div className="panel p-5 text-sm text-slate-400">
        Backend status: {health?.status || 'unknown'} • Live feeds available: {String(health?.live_feeds_available ?? false)} • Auth enforced: {String(health?.auth_enforced ?? false)}
      </div>
    </div>
  )
}
