import { create } from 'zustand'

export const useWsStore = create((set) => ({
  feedStatus: null,
  connected: false,
  liveAlerts: [],
  systemScan: {
    sessionId: null,
    status: 'idle',
    progress: 0,
    currentAsset: null,
    assetsScanned: 0,
    totalAssets: 0,
    summary: null,
  },
  deviceScan: {
    sessionId: null,
    status: 'idle',
    phase: null,
    progress: 0,
    message: '',
    liveStats: { found: 0, flagged: 0 },
    summary: null,
    dismissComplete: false,
  },
  pipeline: {
    isRunning: false,
    runId: null,
    currentTask: null,
    progress: 0,
    taskStatuses: {},
    lastRun: null,
  },
  setFeedStatus: (feedStatus) => set({ feedStatus }),
  setConnected: (connected) => set({ connected }),
  pushLiveAlert: (alert) => set((state) => ({ liveAlerts: [alert, ...state.liveAlerts].slice(0, 50) })),
  setSystemScanSnapshot: (session) =>
    set((state) => ({
      systemScan: {
        ...state.systemScan,
        sessionId: session?.id || state.systemScan.sessionId,
        status: session?.status || state.systemScan.status,
        progress: session?.status === 'complete' ? 100 : state.systemScan.progress,
        currentAsset: null,
        assetsScanned: session?.assets_scanned ?? state.systemScan.assetsScanned,
        totalAssets: session?.assets_scanned ?? state.systemScan.totalAssets,
        summary: session,
      },
    })),
  setPipelineSnapshot: (snapshot) =>
    set((state) => ({
      pipeline: {
        ...state.pipeline,
        isRunning: snapshot?.status === 'running',
        runId: snapshot?.run_id ?? state.pipeline.runId,
        currentTask: snapshot?.current_task ?? state.pipeline.currentTask,
        progress: snapshot?.progress_pct ?? state.pipeline.progress,
        lastRun: snapshot
          ? {
              completedAt: snapshot.completed_at,
              passed: snapshot.tasks_passed,
              failed: snapshot.tasks_failed,
              duration_ms: snapshot.duration_ms,
              status: snapshot.status,
            }
          : state.pipeline.lastRun,
        taskStatuses: Object.fromEntries(
          (snapshot?.steps || []).map((step) => [
            step.task,
            { status: step.status, summary: step.summary, duration: step.duration_ms, error: step.error },
          ]),
        ),
      },
    })),
  handlePipelineEvent: (event) =>
    set((state) => {
      const pipeline = { ...state.pipeline }
      if (event.type === 'pipeline_start') {
        pipeline.isRunning = true
        pipeline.runId = event.run_id
        pipeline.progress = 0
        pipeline.currentTask = null
        pipeline.taskStatuses = {}
      }
      if (event.type === 'task_start') {
        pipeline.isRunning = true
        pipeline.runId = event.run_id
        pipeline.currentTask = event.task
        pipeline.taskStatuses = {
          ...pipeline.taskStatuses,
          [event.task]: { status: 'running', summary: 'Running...', duration: 0 },
        }
      }
      if (event.type === 'task_complete') {
        pipeline.progress = event.progress_pct ?? pipeline.progress
        pipeline.currentTask = event.task
        pipeline.taskStatuses = {
          ...pipeline.taskStatuses,
          [event.task]: {
            status: event.status,
            summary: event.summary,
            duration: event.duration_ms,
            error: event.error,
            data: event.data,
          },
        }
      }
      if (event.type === 'pipeline_done') {
        pipeline.isRunning = false
        pipeline.progress = 100
        pipeline.lastRun = {
          completedAt: event.completed_at,
          passed: event.passed,
          failed: event.failed,
          duration_ms: event.duration_ms,
          status: event.status,
        }
      }
      return { pipeline }
    }),
  handleSystemScanEvent: (event) =>
    set((state) => {
      const systemScan = { ...state.systemScan }
      if (event.type === 'system_scan_progress') {
        systemScan.sessionId = event.session_id
        systemScan.status = 'running'
        systemScan.progress = event.progress_pct ?? systemScan.progress
        systemScan.currentAsset = event.current_asset
        systemScan.assetsScanned = event.assets_scanned ?? systemScan.assetsScanned
        systemScan.totalAssets = event.total_assets ?? systemScan.totalAssets
      }
      if (event.type === 'system_scan_complete') {
        systemScan.sessionId = event.session_id
        systemScan.status = 'complete'
        systemScan.progress = 100
        systemScan.currentAsset = null
        systemScan.assetsScanned = event.summary?.assets_scanned ?? systemScan.assetsScanned
        systemScan.totalAssets = event.summary?.assets_scanned ?? systemScan.totalAssets
        systemScan.summary = event.summary
      }
      return { systemScan }
    }),
  handleDeviceScanEvent: (event) =>
    set((state) => {
      const deviceScan = { ...state.deviceScan }
      if (event.type === 'device_scan_started' || event.event === 'device_scan_started') {
        deviceScan.sessionId = event.sessionId
        deviceScan.status = 'running'
        deviceScan.progress = 0
        deviceScan.dismissComplete = false
      }
      if (event.type === 'device_scan_progress' || event.event === 'device_scan_progress') {
        deviceScan.sessionId = event.sessionId ?? deviceScan.sessionId
        deviceScan.status = 'running'
        deviceScan.phase = event.phase
        deviceScan.progress = event.percent ?? deviceScan.progress
        deviceScan.message = event.message ?? deviceScan.message
        deviceScan.liveStats = event.liveStats ?? deviceScan.liveStats
      }
      if (event.type === 'device_scan_complete' || event.event === 'device_scan_complete') {
        deviceScan.sessionId = event.sessionId ?? deviceScan.sessionId
        deviceScan.status = 'complete'
        deviceScan.progress = 100
        deviceScan.summary = event.summary
        deviceScan.message = ''
      }
      return { deviceScan }
    }),
  dismissDeviceScanBanner: () =>
    set((state) => ({
      deviceScan: { ...state.deviceScan, dismissComplete: true, status: 'idle' },
    })),
}))
