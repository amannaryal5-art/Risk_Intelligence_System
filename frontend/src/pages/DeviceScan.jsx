import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Activity, AppWindow, Globe, HardDrive, Network, Play, Power, Server } from 'lucide-react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import client from '../api/client'
import Spinner from '../components/ui/Spinner'
import { formatDate, truncate } from '../lib/utils'
import { useWsStore } from '../store/wsStore'
import { useAuthStore } from '../store/authStore'

const PHASES = ['sysinfo', 'network', 'processes', 'ports', 'software', 'dns', 'startup']

function riskColor(score) {
  const s = Number(score || 0)
  if (s <= 30) return '#00ff88'
  if (s <= 69) return '#ff9500'
  return '#ff3b30'
}

function VerdictBadge({ verdict }) {
  const v = String(verdict || 'clean').toLowerCase()
  const cls =
    v === 'malicious'
      ? 'border-red-500/50 bg-red-950/40 text-red-300 animate-pulse'
      : v === 'suspicious'
        ? 'border-orange-500/50 bg-orange-950/30 text-orange-200'
        : 'border-emerald-700/40 bg-emerald-950/30 text-emerald-200'
  return <span className={`rounded-full border px-2 py-0.5 text-xs font-medium uppercase ${cls}`}>{v}</span>
}

function minutesAgo(value) {
  if (!value) return 'Never'
  const diff = Date.now() - new Date(value).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins} minutes ago`
  const hrs = Math.floor(mins / 60)
  return `${hrs}h ${mins % 60}m ago`
}

function ConfirmModal({ open, title, children, onCancel, onConfirm, confirmLabel, confirmDisabled }) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4">
      <div className="panel-elevated w-full max-w-md p-6">
        <p className="font-mono text-lg text-slate-50">{title}</p>
        <div className="mt-4 text-sm text-slate-300">{children}</div>
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" className="btn-secondary" onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="btn-primary" disabled={confirmDisabled} onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

function DeviceOverviewCard({ sysinfo, latest, deviceScan, onScan, scheduleMutation }) {
  const [scheduleOpen, setScheduleOpen] = useState(false)
  const [intervalMinutes, setIntervalMinutes] = useState(360)
  const [scheduleEnabled, setScheduleEnabled] = useState(false)
  const score = latest?.overall_risk_score ?? sysinfo?.risk_score ?? 0
  const running = deviceScan.status === 'running'

  return (
    <div className="panel-elevated p-6">
      <div className="flex flex-wrap items-start justify-between gap-6">
        <div>
          <p className="section-title">Host Overview</p>
          <p className="mt-2 font-mono text-2xl text-slate-50">{sysinfo?.hostname || 'Unknown host'}</p>
          <p className="mt-1 text-sm text-slate-400">
            {sysinfo?.os_name || sysinfo?.system?.os_name || 'OS'} {sysinfo?.os_version || ''}
          </p>
          <div className="mt-4 grid gap-2 text-sm text-slate-300 md:grid-cols-2">
            <span>User: {sysinfo?.current_user || '—'}</span>
            <span>Last scan: {minutesAgo(sysinfo?.last_scan)}</span>
            <span className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${String(sysinfo?.firewall_status || '').includes('active') ? 'bg-emerald-400' : 'bg-red-500'}`} />
              Firewall: {sysinfo?.firewall_status || 'unknown'}
            </span>
            <span className="flex items-center gap-2">
              <span
                className={`h-2 w-2 rounded-full ${
                  ['detected', 'on', 'enabled'].some((s) => String(sysinfo?.av_status || '').toLowerCase().includes(s))
                    ? 'bg-emerald-400'
                    : 'bg-orange-400'
                }`}
              />
              AV: {sysinfo?.av_status || 'unknown'}
            </span>
          </div>
        </div>
        <div className="text-center">
          <p className="section-title">Device Risk Score</p>
          <p
            className="mt-2 font-mono text-6xl font-bold"
            style={{ color: riskColor(score), textShadow: score > 69 ? `0 0 24px ${riskColor(score)}55` : undefined }}
          >
            {Math.round(score)}
          </p>
        </div>
      </div>

      {running ? (
        <div className="mt-6 space-y-3">
          <div className="flex justify-between text-sm text-cyan-200">
            <span>{deviceScan.message || 'Scanning…'}</span>
            <span>{deviceScan.progress}%</span>
          </div>
          <div className="h-3 rounded-full bg-slate-900">
            <div className="h-3 rounded-full bg-cyan-500 transition-all" style={{ width: `${deviceScan.progress}%` }} />
          </div>
          <div className="flex flex-wrap gap-2 text-xs">
            {PHASES.map((phase) => {
              const idx = PHASES.indexOf(phase)
              const cur = PHASES.indexOf(deviceScan.phase)
              const done = cur > idx || deviceScan.progress >= 100
              const active = deviceScan.phase === phase
              return (
                <span
                  key={phase}
                  className={`rounded-lg border px-2 py-1 capitalize ${done ? 'border-emerald-700/50 text-emerald-300' : active ? 'border-cyan-600/50 text-cyan-200' : 'border-border text-slate-500'}`}
                >
                  {phase} {done ? '✓' : active ? '…' : ''}
                </span>
              )
            })}
          </div>
        </div>
      ) : (
        <div className="mt-6 flex flex-wrap gap-3">
          <button type="button" className="btn-primary" onClick={onScan}>
            <Play className="mr-2 inline h-4 w-4" />
            Run Full Device Scan
          </button>
          <button type="button" className="btn-secondary" onClick={() => setScheduleOpen((v) => !v)}>
            Schedule Scans
          </button>
        </div>
      )}

      {scheduleOpen ? (
        <div className="mt-4 flex flex-wrap items-end gap-3 rounded-xl border border-border bg-slate-950/50 p-4">
          <label className="text-sm text-slate-400">
            Interval (minutes)
            <input className="field mt-1 w-28" type="number" min={5} value={intervalMinutes} onChange={(e) => setIntervalMinutes(Number(e.target.value))} />
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={scheduleEnabled} onChange={(e) => setScheduleEnabled(e.target.checked)} />
            Enable
          </label>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => scheduleMutation.mutate({ enabled: scheduleEnabled, intervalMinutes }, { onSuccess: () => toast.success('Schedule saved') })}
          >
            Save
          </button>
        </div>
      ) : null}
    </div>
  )
}

export default function DeviceScan() {
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const deviceScan = useWsStore((s) => s.deviceScan)
  const [connPage, setConnPage] = useState(1)
  const [procPage, setProcPage] = useState(1)
  const [expandedConn, setExpandedConn] = useState(null)
  const [expandedProc, setExpandedProc] = useState(null)
  const [killModal, setKillModal] = useState(null)
  const [blockModal, setBlockModal] = useState(null)
  const [killConfirmText, setKillConfirmText] = useState('')

  const sysQuery = useQuery({
    queryKey: ['device', 'sysinfo'],
    queryFn: async () => (await client.get('/api/device/sysinfo')).data,
    refetchInterval: deviceScan.status === 'running' ? 5000 : false,
  })

  const latestQuery = useQuery({
    queryKey: ['device', 'latest'],
    queryFn: async () => (await client.get('/api/device/scan/latest')).data,
    retry: false,
    refetchInterval: deviceScan.status === 'running' ? 8000 : false,
  })

  const historyQuery = useQuery({
    queryKey: ['device', 'history'],
    queryFn: async () => (await client.get('/api/device/scan/history')).data,
  })

  const sessionId = latestQuery.data?.id
  const connQuery = useQuery({
    queryKey: ['device', 'connections', sessionId, connPage],
    enabled: !!sessionId,
    queryFn: async () => (await client.get(`/api/device/scan/${sessionId}/connections`, { params: { page: connPage, limit: 20 } })).data,
  })

  const procQuery = useQuery({
    queryKey: ['device', 'processes', sessionId, procPage],
    enabled: !!sessionId,
    queryFn: async () => (await client.get(`/api/device/scan/${sessionId}/processes`, { params: { page: procPage, limit: 20 } })).data,
  })

  const scanMutation = useMutation({
    mutationFn: async () => (await client.post('/api/device/scan')).data,
    onSuccess: () => toast.success('Device scan started'),
  })

  const scheduleMutation = useMutation({
    mutationFn: async (body) => (await client.post('/api/device/scan/schedule', body)).data,
  })

  const killMutation = useMutation({
    mutationFn: async ({ pid, sessionId: sid }) => (await client.post('/api/device/process/kill', { pid, sessionId: sid })).data,
    onSuccess: () => {
      toast.success('Process terminated')
      setKillModal(null)
      setKillConfirmText('')
    },
    onError: (e) => toast.error(e.response?.data?.detail || 'Kill failed'),
  })

  const blockMutation = useMutation({
    mutationFn: async ({ ip }) => (await client.post('/api/device/ip/block', { ip, reason: 'CRIE analyst block' })).data,
    onSuccess: () => {
      toast.success('IP blocked')
      setBlockModal(null)
    },
    onError: (e) => toast.error(e.response?.data?.detail || 'Block failed'),
  })

  useEffect(() => {
    if (deviceScan.status === 'complete') {
      queryClient.invalidateQueries({ queryKey: ['device'] })
    }
  }, [deviceScan.status, queryClient])

  const latest = latestQuery.data
  const chartData = useMemo(
    () => (historyQuery.data || []).map((row) => ({ ...row, score: row.overall_risk_score, label: formatDate(row.triggered_at).slice(11, 16) })),
    [historyQuery.data],
  )

  const tiles = [
    { key: 'connections', label: 'Network Connections', icon: Network, total: latest?.connections_found, flagged: latest?.connections_flagged },
    { key: 'processes', label: 'Running Processes', icon: Activity, total: latest?.processes_found, flagged: latest?.processes_flagged },
    { key: 'ports', label: 'Open Ports', icon: Server, total: latest?.ports_open, flagged: latest?.ports_suspicious },
    { key: 'software', label: 'Installed Software', icon: AppWindow, total: latest?.software_count, flagged: 0 },
    { key: 'dns', label: 'DNS Cache', icon: Globe, total: latest?.dns_entries_checked, flagged: latest?.dns_flagged },
    { key: 'startup', label: 'Startup Items', icon: Power, total: latest?.startup_items, flagged: latest?.startup_flagged },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <HardDrive className="h-8 w-8 text-cyan-400" />
        <div>
          <h1 className="font-mono text-2xl text-slate-50">Device Scan</h1>
          <p className="text-sm text-slate-400">Host EDR — network, processes, ports, DNS, startup</p>
        </div>
      </div>

      <DeviceOverviewCard sysinfo={sysQuery.data} latest={latest} deviceScan={deviceScan} onScan={() => scanMutation.mutate()} scheduleMutation={scheduleMutation} />

      {latest ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {tiles.map((tile) => {
            const Icon = tile.icon
            const border = tile.flagged > 0 ? 'border-orange-500/40' : 'border-emerald-700/30'
            return (
              <button
                key={tile.key}
                type="button"
                className={`panel p-5 text-left ${border}`}
                onClick={() => document.getElementById(tile.key)?.scrollIntoView({ behavior: 'smooth' })}
              >
                <Icon className="h-5 w-5 text-cyan-400" />
                <p className="mt-3 text-sm font-medium text-slate-100">{tile.label}</p>
                <p className="mt-1 text-xs text-slate-500">
                  {tile.total ?? 0} total {tile.flagged > 0 ? `· ${tile.flagged} flagged` : ''}
                </p>
              </button>
            )
          })}
        </div>
      ) : null}

      {latestQuery.isLoading ? (
        <div className="panel flex min-h-[120px] items-center justify-center">
          <Spinner />
        </div>
      ) : !latest ? (
        <div className="panel p-6 text-sm text-slate-400">No device scan session yet. Run a scan to populate host telemetry.</div>
      ) : (
        <>
          <div id="connections" className="panel p-5 scroll-mt-24">
            <p className="section-title">Network Connections</p>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-slate-500">
                  <tr>
                    {['Process', 'PID', 'Local', 'Remote IP', 'Port', 'State', 'Verdict'].map((h) => (
                      <th key={h} className="px-3 py-2">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(connQuery.data?.items || []).map((row) => (
                    <>
                      <tr key={row.id} className="border-t border-border/60 hover:bg-slate-900/40" onClick={() => setExpandedConn(expandedConn === row.id ? null : row.id)}>
                        <td className="px-3 py-2">{row.process_name}</td>
                        <td className="px-3 py-2">{row.pid}</td>
                        <td className="px-3 py-2">{row.local_port}</td>
                        <td className="px-3 py-2">{row.remote_ip}</td>
                        <td className="px-3 py-2">{row.remote_port}</td>
                        <td className="px-3 py-2">{row.state}</td>
                        <td className="px-3 py-2">
                          <VerdictBadge verdict={row.verdict} />
                        </td>
                      </tr>
                      {expandedConn === row.id ? (
                        <tr>
                          <td colSpan={7} className="bg-slate-950/80 px-4 py-3 text-xs text-slate-400">
                            <p className="font-mono">{row.process_path}</p>
                            <div className="mt-2 flex gap-2">
                              <button type="button" className="btn-secondary" onClick={() => setBlockModal(row)}>
                                Block IP
                              </button>
                              {user?.role === 'admin' ? (
                                <button type="button" className="btn-primary" onClick={() => setKillModal(row)}>
                                  Kill Process
                                </button>
                              ) : null}
                            </div>
                          </td>
                        </tr>
                      ) : null}
                    </>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3 flex justify-end gap-2">
              <button type="button" className="btn-secondary" disabled={connPage <= 1} onClick={() => setConnPage((p) => p - 1)}>
                Prev
              </button>
              <button type="button" className="btn-secondary" disabled={connPage * 20 >= (connQuery.data?.total || 0)} onClick={() => setConnPage((p) => p + 1)}>
                Next
              </button>
            </div>
          </div>

          <div id="processes" className="panel p-5 scroll-mt-24">
            <p className="section-title">Running Processes</p>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-slate-500">
                  <tr>
                    {['Name', 'PID', 'CPU%', 'Mem MB', 'Path', 'VT', 'Verdict'].map((h) => (
                      <th key={h} className="px-3 py-2">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(procQuery.data?.items || []).map((row) => (
                    <>
                      <tr key={row.id} className="border-t border-border/60" onClick={() => setExpandedProc(expandedProc === row.id ? null : row.id)}>
                        <td className="px-3 py-2">{row.name}</td>
                        <td className="px-3 py-2">{row.pid}</td>
                        <td className="px-3 py-2">{row.cpu_percent}</td>
                        <td className="px-3 py-2">{row.memory_mb?.toFixed?.(0)}</td>
                        <td className="px-3 py-2" title={row.path}>
                          {truncate(row.path, 36)}
                        </td>
                        <td className="px-3 py-2">
                          {row.vt_positives != null ? `${row.vt_positives}/${row.vt_total || 87}` : '—'}
                        </td>
                        <td className="px-3 py-2">
                          <VerdictBadge verdict={row.verdict} />
                        </td>
                      </tr>
                      {expandedProc === row.id ? (
                        <tr>
                          <td colSpan={7} className="bg-slate-950/80 px-4 py-3 text-xs">
                            <p className="font-mono break-all">{row.sha256_hash}</p>
                            {user?.role === 'admin' ? (
                              <button type="button" className="btn-primary mt-2" onClick={() => setKillModal(row)}>
                                Kill Process
                              </button>
                            ) : null}
                          </td>
                        </tr>
                      ) : null}
                    </>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div id="dns" className="panel p-5 scroll-mt-24">
            <p className="section-title">DNS / Hosts (flagged)</p>
            <div className="mt-3 space-y-2">
              {((latest.full_results?.dns?.flagged) || []).map((entry, i) => (
                <div key={i} className="rounded-xl border border-border bg-slate-950/50 px-4 py-3 text-sm flex justify-between">
                  <span>{entry.domain}</span>
                  <VerdictBadge verdict={entry.verdict} />
                </div>
              ))}
              {!((latest.full_results?.dns?.flagged) || []).length ? <p className="text-sm text-slate-500">No flagged entries.</p> : null}
            </div>
          </div>

          <div className="panel p-5">
            <p className="section-title">Risk score history</p>
            <div className="mt-4 h-64">
              {chartData.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chartData}>
                    <CartesianGrid stroke="#1e2a3a" strokeDasharray="3 3" />
                    <XAxis dataKey="label" stroke="#64748b" />
                    <YAxis domain={[0, 100]} stroke="#64748b" />
                    <Tooltip />
                    <ReferenceLine y={30} stroke="#00ff88" strokeDasharray="4 4" />
                    <ReferenceLine y={70} stroke="#ff3b30" strokeDasharray="4 4" />
                    <Line type="monotone" dataKey="score" stroke="#00d8ff" strokeWidth={2} dot />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <p className="text-sm text-slate-500">No history yet.</p>
              )}
            </div>
          </div>
        </>
      )}

      <ConfirmModal
        open={!!blockModal}
        title={`Block outbound traffic to ${blockModal?.remote_ip}?`}
        onCancel={() => setBlockModal(null)}
        onConfirm={() => blockMutation.mutate({ ip: blockModal.remote_ip })}
        confirmLabel="Confirm Block"
      >
        <p>Host firewall rule will block outbound traffic to this IP.</p>
      </ConfirmModal>

      <ConfirmModal
        open={!!killModal}
        title={`Terminate ${killModal?.process_name || killModal?.name} (PID ${killModal?.pid})?`}
        onCancel={() => {
          setKillModal(null)
          setKillConfirmText('')
        }}
        onConfirm={() => killMutation.mutate({ pid: killModal.pid, sessionId: latest?.id })}
        confirmLabel="Kill Process"
        confirmDisabled={killConfirmText !== 'CONFIRM'}
      >
        <p className="mb-2">Type CONFIRM to enable.</p>
        <input className="field" value={killConfirmText} onChange={(e) => setKillConfirmText(e.target.value)} />
      </ConfirmModal>
    </div>
  )
}
