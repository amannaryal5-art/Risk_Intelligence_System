import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import client from '../api/client'
import { useWsStore } from '../store/wsStore'

export function usePipeline() {
  const pipeline = useWsStore((state) => state.pipeline)
  const setPipelineSnapshot = useWsStore((state) => state.setPipelineSnapshot)

  const query = useQuery({
    queryKey: ['autopilot', 'last-run'],
    queryFn: async () => (await client.get('/api/autopilot/last-run')).data,
    retry: false,
  })

  useEffect(() => {
    if (query.data) setPipelineSnapshot(query.data)
  }, [query.data, setPipelineSnapshot])

  return {
    isRunning: pipeline.isRunning,
    currentTask: pipeline.currentTask,
    progress: pipeline.progress,
    lastRun: pipeline.lastRun,
    taskStatuses: pipeline.taskStatuses,
    runId: pipeline.runId,
  }
}
