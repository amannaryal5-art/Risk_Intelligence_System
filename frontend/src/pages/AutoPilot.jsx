import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import client from '../api/client'
import { usePipeline } from '../hooks/usePipeline'

const TASKS = [
  ['run_device_scan', 'Run Device Scan'],
  ['health_check', 'Health check'],
  ['probe_live_feeds', 'Probe live feeds'],
  ['run_aria_monitoring_cycle', 'Run ARIA monitoring cycle'],
  ['run_unified_intelligence_scan', 'Run Unified Intelligence Scan'],
  ['sync_software_inventory', 'Sync Software Inventory'],
  ['rescan_all_assets', 'Re-scan all assets'],
  ['refresh_alert_queue', 'Refresh alert queue'],
  ['generate_daily_report', 'Generate daily report'],
  ['sync_case_store', 'Sync case store'],
  ['update_aria_stats', 'Update ARIA stats'],
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
        {pipeline.isRunning ? (
          <>
            <div className="flex items-center justify-between text-sm text-cyan-300">
              <span>Running - {pipeline.currentTask || 'Starting pipeline'}</span>
              <span>{pipeline.progress}%</span>
            </div>
            <div className="mt-3 h-3 rounded-full bg-slate-900">
              <div className="h-3 rounded-full bg-cyan-500 transition-all" style={{ width: `${pipeline.progress}%` }} />
            </div>
          </>
        ) : pipeline.lastRun ? (
          <p className="text-sm text-slate-300">
            Pipeline completed in {pipeline.lastRun.duration_ms || 0}ms - {pipeline.lastRun.passed || 0} passed, {pipeline.lastRun.failed || 0} failed
          </p>
        ) : (
          <p className="text-sm text-slate-400">No pipeline run recorded yet.</p>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {TASKS.map(([id, label]) => {
          const state = pipeline.taskStatuses[id]
          const status = state?.status || 'waiting'
          return (
            <div key={id} className="panel p-5">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="font-medium text-slate-100">{label}</p>
                  <p className="mt-2 text-sm text-slate-400">{state?.summary || 'Waiting'}</p>
                </div>
                <span className={`text-xs font-semibold uppercase ${status === 'success' ? 'text-emerald-400' : status === 'failed' ? 'text-red-400' : status === 'running' ? 'text-cyan-300' : 'text-slate-500'}`}>
                  {status}
                </span>
              </div>
              <div className="mt-4 flex items-center justify-between text-xs text-slate-500">
                <span>{state?.duration ? `${state.duration}ms` : 'Idle'}</span>
                <button type="button" className="btn-secondary" onClick={() => runTask(id)} disabled={pipeline.isRunning || busyTask === id}>
                  Run
                </button>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
