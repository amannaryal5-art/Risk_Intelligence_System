import { useCallback, useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import client from '../api/client'

const TASKS = [
  {
    id: 'health',
    label: 'Health check',
    description: 'Ping backend and verify the API is alive.',
    icon: '🩺',
    run: async () => {
      const res = await client.get('/api/v1/health')
      return { ok: true, detail: `Status: ${res.data?.status ?? 'ok'}` }
    },
  },
  {
    id: 'feeds',
    label: 'Probe live feeds',
    description: 'Test OTX, AbuseIPDB, VirusTotal, and URLScan connectivity.',
    icon: '📡',
    run: async () => {
      const res = await client.get('/api/v1/feeds/probe')
      const feeds = res.data?.feeds ?? []
      const live = feeds.filter((feed) => feed.auth_valid).length
      return { ok: true, detail: `${live}/${feeds.length} feeds live` }
    },
  },
  {
    id: 'monitoring',
    label: 'Run ARIA monitoring cycle',
    description: 'Scan all overdue assets for new threats.',
    icon: '🔍',
    run: async () => {
      const res = await client.post('/api/aria/monitoring/run')
      const count = res.data?.scanned ?? res.data?.count ?? 0
      return { ok: true, detail: `${count} assets scanned` }
    },
  },
  {
    id: 'assets',
    label: 'Re-scan all assets',
    description: 'Trigger an immediate scan for every registered asset.',
    icon: '🛡️',
    run: async () => {
      const listRes = await client.get('/api/aria/assets')
      const assets = Array.isArray(listRes.data) ? listRes.data : listRes.data?.assets ?? []
      let queued = 0

      await Promise.allSettled(
        assets.map(async (asset) => {
          await client.post(`/api/aria/assets/${asset.id}/scan`)
          queued += 1
        }),
      )

      return { ok: true, detail: `${queued}/${assets.length} assets queued` }
    },
  },
  {
    id: 'alerts',
    label: 'Refresh alert queue',
    description: 'Pull the latest ARIA alerts and count unseen items.',
    icon: '🔔',
    run: async () => {
      const res = await client.get('/api/aria/alerts')
      const alerts = Array.isArray(res.data) ? res.data : []
      const unseen = alerts.filter((alert) => !alert.seen).length
      return { ok: true, detail: `${alerts.length} alerts, ${unseen} unseen` }
    },
  },
  {
    id: 'report',
    label: 'Generate daily report',
    description: 'Generate the latest ARIA intelligence report.',
    icon: '📊',
    run: async () => {
      const res = await client.post('/api/aria/reports/generate')
      const id = res.data?.id ?? res.data?.report_id ?? 'generated'
      return { ok: true, detail: `Report #${id} ready` }
    },
  },
  {
    id: 'cases',
    label: 'Sync case store',
    description: 'Refresh open cases from the backend.',
    icon: '📁',
    run: async () => {
      const res = await client.get('/api/v1/cases')
      const count = res.data?.count ?? (Array.isArray(res.data) ? res.data.length : 0)
      return { ok: true, detail: `${count} cases loaded` }
    },
  },
  {
    id: 'stats',
    label: 'Update ARIA stats',
    description: 'Refresh asset and risk distribution counters.',
    icon: '📈',
    run: async () => {
      const res = await client.get('/api/aria/stats')
      const { total = 0, critical = 0, high = 0 } = res.data ?? {}
      return { ok: true, detail: `${total} assets, ${critical} critical, ${high} high` }
    },
  },
]

const STATUS = {
  idle: 'idle',
  running: 'running',
  done: 'done',
  error: 'error',
  skip: 'skip',
}

function useAutoInterval(callback, intervalMs, active) {
  const callbackRef = useRef(callback)

  useEffect(() => {
    callbackRef.current = callback
  }, [callback])

  useEffect(() => {
    if (!active) return undefined
    const id = window.setInterval(() => callbackRef.current(), intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs, active])
}

export default function AutoPilot() {
  const queryClient = useQueryClient()
  const [taskStates, setTaskStates] = useState(() =>
    Object.fromEntries(TASKS.map((task) => [task.id, { status: STATUS.idle, detail: '', ms: 0 }])),
  )
  const [running, setRunning] = useState(false)
  const [autoMode, setAutoMode] = useState(false)
  const [autoIntervalMin, setAutoIntervalMin] = useState(10)
  const [log, setLog] = useState([])
  const [selected, setSelected] = useState(() => new Set(TASKS.map((task) => task.id)))
  const [lastRun, setLastRun] = useState(null)
  const logRef = useRef(null)

  const addLog = useCallback((message, type = 'info') => {
    const ts = new Date().toLocaleTimeString()
    setLog((current) => [...current.slice(-199), { ts, message, type }])
  }, [])

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [log])

  const runAll = useCallback(async () => {
    if (running) return

    setRunning(true)
    const toRun = TASKS.filter((task) => selected.has(task.id))
    addLog(`Starting ${toRun.length} task(s)...`, 'start')

    setTaskStates((current) => {
      const next = { ...current }
      TASKS.forEach((task) => {
        next[task.id] = selected.has(task.id)
          ? { status: STATUS.idle, detail: '', ms: 0 }
          : { ...current[task.id], status: STATUS.skip }
      })
      return next
    })

    for (const task of toRun) {
      const startedAt = Date.now()
      setTaskStates((current) => ({
        ...current,
        [task.id]: { status: STATUS.running, detail: 'Running...', ms: 0 },
      }))
      addLog(`-> ${task.label}`)

      try {
        const result = await task.run()
        const ms = Date.now() - startedAt
        setTaskStates((current) => ({
          ...current,
          [task.id]: { status: STATUS.done, detail: result.detail, ms },
        }))
        addLog(`OK ${task.label} - ${result.detail} (${ms}ms)`, 'ok')
      } catch (error) {
        const ms = Date.now() - startedAt
        const detail = error?.response?.data?.detail ?? error?.message ?? 'Unknown error'
        setTaskStates((current) => ({
          ...current,
          [task.id]: { status: STATUS.error, detail, ms },
        }))
        addLog(`ERR ${task.label} - ${detail}`, 'err')
      }
    }

    queryClient.invalidateQueries()
    const finishedAt = new Date()
    setLastRun(finishedAt)
    addLog(`Done at ${finishedAt.toLocaleTimeString()}`, 'start')
    setRunning(false)
  }, [addLog, queryClient, running, selected])

  useAutoInterval(runAll, autoIntervalMin * 60 * 1000, autoMode && !running)

  const allDone = TASKS.every((task) => {
    const status = taskStates[task.id]?.status
    return status === STATUS.done || status === STATUS.error || status === STATUS.skip
  })
  const anyError = TASKS.some((task) => taskStates[task.id]?.status === STATUS.error)

  const toggleSelect = (id) => {
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const statusClasses = {
    [STATUS.idle]: 'text-slate-500',
    [STATUS.running]: 'text-blue-400',
    [STATUS.done]: 'text-emerald-400',
    [STATUS.error]: 'text-red-400',
    [STATUS.skip]: 'text-slate-400',
  }

  const statusIcons = {
    [STATUS.idle]: '○',
    [STATUS.running]: '◌',
    [STATUS.done]: '✓',
    [STATUS.error]: '✗',
    [STATUS.skip]: '–',
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="panel p-6">
        <h1 className="font-mono text-2xl text-slate-50">AutoPilot</h1>
        <p className="mt-2 max-w-3xl text-sm text-slate-400">
          Run recurring CRIE operational tasks from one place, or enable scheduled auto-mode to keep the platform fresh without manual refreshes.
        </p>
      </div>

      <div className="panel p-5">
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={runAll}
            disabled={running}
            className={`rounded-xl px-6 py-3 text-sm font-semibold text-white transition ${
              running
                ? 'cursor-not-allowed bg-slate-700'
                : anyError && allDone
                  ? 'bg-red-800 hover:bg-red-700'
                  : allDone
                    ? 'bg-emerald-700 hover:bg-emerald-600'
                    : 'bg-blue-600 hover:bg-blue-500'
            }`}
          >
            {running ? 'Running...' : allDone ? 'Run Again' : 'Run All Now'}
          </button>

          <label className="flex items-center gap-3 text-sm text-slate-300">
            <button
              type="button"
              onClick={() => setAutoMode((value) => !value)}
              className={`relative h-6 w-11 rounded-full transition ${autoMode ? 'bg-blue-600' : 'bg-slate-700'}`}
            >
              <span className={`absolute top-1 h-4 w-4 rounded-full bg-white transition ${autoMode ? 'left-6' : 'left-1'}`} />
            </button>
            Auto mode
          </label>

          {autoMode ? (
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <span>every</span>
              <select
                className="field w-28 py-2"
                value={autoIntervalMin}
                onChange={(event) => setAutoIntervalMin(Number(event.target.value))}
              >
                {[5, 10, 15, 30, 60].map((minutes) => (
                  <option key={minutes} value={minutes}>
                    {minutes} min
                  </option>
                ))}
              </select>
            </div>
          ) : null}

          {lastRun ? (
            <span className="ml-auto text-xs text-slate-500">Last run: {lastRun.toLocaleTimeString()}</span>
          ) : null}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {TASKS.map((task) => {
          const state = taskStates[task.id]
          const isSelected = selected.has(task.id)

          return (
            <button
              key={task.id}
              type="button"
              onClick={() => {
                if (!running) toggleSelect(task.id)
              }}
              className={`panel relative p-5 text-left transition ${
                isSelected ? 'border-blue-500/40 bg-blue-950/20' : 'border-border'
              } ${running && state.status === STATUS.idle ? 'opacity-60' : ''}`}
            >
              <span
                className={`absolute right-4 top-4 flex h-5 w-5 items-center justify-center rounded border text-[11px] ${
                  isSelected ? 'border-blue-500 bg-blue-600 text-white' : 'border-slate-600 text-transparent'
                }`}
              >
                ✓
              </span>

              <div className="text-2xl">{task.icon}</div>
              <p className="mt-3 text-sm font-semibold text-slate-100">{task.label}</p>
              <p className="mt-2 text-xs text-slate-500">{task.description}</p>

              <div className="mt-4 flex items-center gap-2">
                <span className={`font-mono text-sm ${statusClasses[state.status]}`}>{statusIcons[state.status]}</span>
                <span className={`text-xs ${statusClasses[state.status]}`}>
                  {state.status === STATUS.running
                    ? 'Running...'
                    : state.status === STATUS.idle
                      ? 'Waiting'
                      : state.status === STATUS.skip
                        ? 'Skipped'
                        : state.detail || state.status}
                </span>
                {state.ms > 0 ? <span className="ml-auto text-[11px] text-slate-500">{state.ms}ms</span> : null}
              </div>

              {state.status === STATUS.running ? (
                <div className="mt-3 h-1 overflow-hidden rounded-full bg-slate-800">
                  <div className="autopilot-progress h-full w-2/3 bg-blue-500" />
                </div>
              ) : null}
            </button>
          )
        })}
      </div>

      <div className="panel overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <p className="section-title">Live Log</p>
          <button type="button" className="text-xs text-slate-500 hover:text-slate-300" onClick={() => setLog([])}>
            Clear
          </button>
        </div>
        <div ref={logRef} className="h-64 overflow-y-auto bg-slate-950/50 px-5 py-4 font-mono text-xs leading-7">
          {log.length ? null : <p className="text-slate-600">Press &quot;Run All Now&quot; to start.</p>}
          {log.map((entry, index) => (
            <div
              key={`${entry.ts}-${index}`}
              className={
                entry.type === 'ok'
                  ? 'text-emerald-400'
                  : entry.type === 'err'
                    ? 'text-red-400'
                    : entry.type === 'start'
                      ? 'text-blue-300'
                      : 'text-slate-400'
              }
            >
              <span className="mr-3 text-slate-600">{entry.ts}</span>
              {entry.message}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
