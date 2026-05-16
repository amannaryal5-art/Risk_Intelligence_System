import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { configureFeeds, getFeedsStatus, probeFeeds } from '../api/feeds'
import FeedDot from '../components/ui/FeedDot'
import Spinner from '../components/ui/Spinner'
import { formatDate } from '../lib/utils'
import { useAuthStore } from '../store/authStore'

export default function FeedStatus() {
  const queryClient = useQueryClient()
  const user = useAuthStore((state) => state.user)
  const [draft, setDraft] = useState({ alienvault_otx: '', abuseipdb: '', virustotal: '' })
  const feedsQuery = useQuery({ queryKey: ['feeds', 'status', 'page'], queryFn: getFeedsStatus })
  const probeMutation = useMutation({
    mutationFn: probeFeeds,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['feeds'] }),
  })
  const configMutation = useMutation({
    mutationFn: () => configureFeeds(draft),
    onSuccess: () => toast.success('Feed configuration updated'),
    onError: (error) => toast.error(error.response?.data?.detail || 'Feed configuration failed'),
  })

  return (
    <div className="space-y-6">
      <div className="flex justify-end">
        <button type="button" className="btn-secondary" disabled={feedsQuery.isFetching} onClick={() => feedsQuery.refetch()}>
          {feedsQuery.isFetching ? <Spinner /> : null}
          Probe feeds now
        </button>
        <button type="button" className="btn-primary ml-3" disabled={probeMutation.isPending} onClick={() => probeMutation.mutate()}>
          {probeMutation.isPending ? <Spinner /> : null}
          Probe All
        </button>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {(feedsQuery.data?.feeds || []).map((feed) => {
          const status = feed.auth_valid ? 'live' : feed.reachable ? 'degraded' : 'offline'
          return (
            <div key={feed.name} className="panel p-5">
              <div className="flex items-center justify-between">
                <p className="font-mono text-lg text-slate-50">{feed.display_name}</p>
                <FeedDot status={status} className="h-3 w-3" />
              </div>
              <div className="mt-4 space-y-2 text-sm text-slate-300">
                <p>Configured: {String(feed.configured)}</p>
                <p>Reachable: {String(feed.reachable)}</p>
                <p>Auth valid: {String(feed.auth_valid)}</p>
                <p>Latency: {feed.latency_ms != null ? `${feed.latency_ms} ms` : '—'}</p>
                <p>HTTP status: {feed.http_status ?? '—'}</p>
                <p>Last checked: {formatDate(feed.last_checked)}</p>
                {feed.error ? <p className="text-red-400">{feed.error}</p> : null}
              </div>
            </div>
          )
        })}
      </div>

      {user?.role === 'admin' ? (
        <div className="panel p-5">
          <p className="section-title">Admin Configuration</p>
          <div className="mt-4 grid gap-3">
            <input className="field" placeholder="AlienVault OTX key" value={draft.alienvault_otx} onChange={(event) => setDraft((current) => ({ ...current, alienvault_otx: event.target.value }))} />
            <input className="field" placeholder="AbuseIPDB key" value={draft.abuseipdb} onChange={(event) => setDraft((current) => ({ ...current, abuseipdb: event.target.value }))} />
            <input className="field" placeholder="VirusTotal key" value={draft.virustotal} onChange={(event) => setDraft((current) => ({ ...current, virustotal: event.target.value }))} />
            <button type="button" className="btn-primary" disabled={configMutation.isPending} onClick={() => configMutation.mutate()}>
              {configMutation.isPending ? <Spinner /> : null}
              Save Feed Keys
            </button>
          </div>
        </div>
      ) : null}
    </div>
  )
}
