import { useEffect, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import client from '../api/client'
import { usePipeline } from '../hooks/usePipeline'

const TASK_GROUPS = [
  {
    phase: 1,
    name: 'Core Checks',
    tasks: [
      { key: 'health_check', name: 'Health check', description: 'Validate API, database, and credentials.' },
      { key: 'probe_live_feeds', name: 'Probe live feeds', description: 'Check reachability and auth for external providers.' },
    ],
  },
  {
    phase: 2,
    name: 'Telemetry',
    tasks: [
      { key: 'run_device_scan', name: 'Run Device Scan', description: 'Collect host telemetry and suspicious process/network data.' },
      { key: 'run_unified_intelligence_scan', name: 'Run Unified Intelligence Scan', description: 'Correlate monitored assets and IOC results.' },
    ],
  },
  {
    phase: 3,
    name: 'Asset Monitoring',
    tasks: [
      { key: 'run_aria_monitoring_cycle', name: 'Run ARIA monitoring cycle', description: 'Scan assets due for evaluation.' },
      { key: 'rescan_all_assets', name: 'Re-scan all assets', description: 'Force a full asset monitoring pass.' },
    ],
  },
  {
    phase: 4,
    name: 'Sync and Queue',
    tasks: [
      { key: 'refresh_alert_queue', name: 'Refresh alert queue', description: 'Promote critical findings into alerting.' },
      { key: 'sync_case_store', name: 'Sync case store', description: 'Relink alerts and open cases.' },
      { key: 'update_aria_stats', name: 'Update ARIA stats', description: 'Refresh dashboard-facing ARIA totals.' },
      { key: 'sync_software_inventory', name: 'Sync Software Inventory', description: 'Capture installed software inventory.' },
    ],
  },
  {
    phase: 5,
    name: 'Reporting',
    tasks: [
      { key: 'generate_daily_report', name: 'Generate daily report', description: 'Create the latest intelligence briefing.' },
    ],
  },
]

export default function AutoPilot() {
  const queryClient = useQueryClient()
  const pipeline = usePipeline()
  const [busyTask, setBusyTask] = useState(null)
  const [autoMode, setAutoMode] = useState(false)
  const [intervalHours, setIntervalHours] = useState(6)

  const scheduleQuery = useQuery({
    queryKey: ['autopilot', 'schedule'],
    queryFn: async () => (await client.get('/api/autopilot/schedule')).data,
  })

  useEffect(() => {
    if (scheduleQuery.data) {
      setAutoMode(Boolean(scheduleQuery.data.enabled))
      setIntervalHours(scheduleQuery.data.interval_hours || 6)
    }
  }, [scheduleQuery.data])

  const runAll = async () => {
    await client.post('/api/autopilot/run-all')
    queryClient.invalidateQueries({ queryKey: ['autopilot', 'last-run'] })
  }

  const runTask = async (task) => {
    setBusyTask(task)
    try {
      await client.post(`/api/autopilot/run-task/${task}`)
    } finally {
      setBusyTask(null)
    }
  }

  const saveSchedule = async (enabled) => {
    setAutoMode(enabled)
    await client.post('/api/autopilot/schedule', { enabled, interval_hours: intervalHours })
    queryClient.invalidateQueries({ queryKey: ['autopilot', 'schedule'] })
  }

  const totalTasks = useMemo(() => TASK_GROUPS.flatMap((group) => group.tasks).length, [])
  const completedTasks = Object.values(pipeline.taskStatuses).filter((task) => ['success', 'failed'].includes(task?.status)).length
  const passedTasks = Object.values(pipeline.taskStatuses).filter((task) => task?.status === 'success').length

  return (
    <div className="space-y-6">
      <div className="panel p-6">
        <h1 className="font-mono text-2xl text-slate-50">AutoPilot</h1>
        <p className="mt-2 text-sm text-slate-400">Run the full CRIE automation pipeline or trigger a single operational task.</p>
      </div>

      <div className="panel p-5">
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="btn-primary" onClick={runAll} disabled={pipeline.isRunning}>
            Run All Tasks
          </button>
          <button type="button" className={autoMode ? 'btn-primary' : 'btn-secondary'} onClick={() => saveSchedule(!autoMode)}>
            Auto Mode {autoMode ? 'ON' : 'OFF'}
          </button>
          <input className="field w-28" type="number" min="1" max="168" value={intervalHours} onChange={(event) => setIntervalHours(Number(event.target.value))} />
          <button type="button" className="btn-secondary" onClick={() => saveSchedule(autoMode)}>
            Save Interval
          </button>
          {scheduleQuery.data?.next_run ? <span className="text-sm text-slate-400">Next run: {scheduleQuery.data.next_run}</span> : null}
        </div>
      </div>

      <div className="panel p-5">
        <div className="mb-3 flex items-center justify-between font-mono text-[11px]">
          <span className={pipeline.isRunning ? 'text-cyber-cyan' : 'text-slate-300'}>
            {pipeline.isRunning ? `> PIPELINE_RUNNING :: ${String(pipeline.currentTask || 'starting').toUpperCase()}` : '> PIPELINE_IDLE'}
          </span>
          <span className="text-slate-500">{completedTasks}/{totalTasks} tasks</span>
        </div>
        <div className="h-2 overflow-hidden rounded-sm border border-border bg-slate-950/80">
          <div className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all" style={{ width: `${pipeline.progress || 0}%` }} />
        </div>
        <div className="mt-3 text-xs text-slate-400">
          {pipeline.isRunning
            ? `${pipeline.progress || 0}% complete`
            : pipeline.lastRun
              ? `Last completed in ${pipeline.lastRun.duration_ms || 0}ms - ${pipeline.lastRun.passed || passedTasks}/${totalTasks} passed`
              : 'No pipeline run recorded yet.'}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {TASK_GROUPS.map((group) => (
          <div key={group.phase} className="contents">
            <div className="md:col-span-2 font-mono text-[10px] tracking-[0.2em] text-slate-500">
              {`── PHASE ${group.phase}: ${group.name.toUpperCase()} ─────────────────────`}
            </div>
            {group.tasks.map((task) => {
              const state = pipeline.taskStatuses[task.key]
              const status = state?.status || 'waiting'
              const border =
                status === 'success'
                  ? 'border-emerald-500/30'
                  : status === 'failed'
                    ? 'border-red-500/30'
                    : status === 'running'
                      ? 'border-cyan-500/40'
                      : 'border-border'
              return (
                <div key={task.key} className={`panel p-5 ${border}`}>
                  <div className="flex items-center justify-between gap-3">
                    <span className={`font-mono text-sm ${status === 'success' ? 'text-emerald-400' : status === 'failed' ? 'text-red-400' : status === 'running' ? 'text-cyan-300' : 'text-slate-200'}`}>
                      {task.name}
                    </span>
                    <span className={`rounded border px-2 py-1 text-[10px] uppercase ${status === 'success' ? 'border-emerald-500/30 text-emerald-400' : status === 'failed' ? 'border-red-500/30 text-red-400' : status === 'running' ? 'border-cyan-500/30 text-cyan-300' : 'border-border text-slate-500'}`}>
                      {status}
                    </span>
                  </div>
                  <div className="mt-3 min-h-[40px] font-mono text-xs text-slate-400">
                    {state?.summary || task.description || 'Waiting...'}
                  </div>
                  <div className="mt-4 flex items-center justify-between text-xs text-slate-500">
                    <span>{state?.duration ? `${state.duration}ms` : '—'}</span>
                    <button type="button" className="btn-secondary" onClick={() => runTask(task.key)} disabled={pipeline.isRunning || busyTask === task.key}>
                      [ RUN ]
                    </button>
                  </div>
                  {status === 'running' ? <div className="scan-sweep mt-3 h-1 rounded bg-cyan-500/70" /> : null}
                </div>
              )
            })}
          </div>
        ))}
      </div>
    </div>
  )
}
