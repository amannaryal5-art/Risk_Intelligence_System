import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { configureFeeds, getFeedsStatus, probeFeeds, testFeedKey } from '../api/feeds'
import Spinner from '../components/ui/Spinner'
import { formatDate } from '../lib/utils'
import { useAuthStore } from '../store/authStore'

export default function FeedStatus() {
  const queryClient = useQueryClient()
  const user = useAuthStore((state) => state.user)
  const [draft, setDraft] = useState({ alienvault_otx: '', abuseipdb: '', virustotal: '', urlscan: '' })
  const [alienVaultTestMessage, setAlienVaultTestMessage] = useState('')
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
  const testKeyMutation = useMutation({
    mutationFn: () => testFeedKey('alienvault', draft.alienvault_otx),
    onSuccess: (result) => setAlienVaultTestMessage(result.message || 'Test completed'),
    onError: (error) => setAlienVaultTestMessage(error.response?.data?.detail || 'Key test failed'),
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
        {(feedsQuery.data?.feeds || []).map((feed) => (
          <div
            key={feed.name}
            style={{
              background: 'var(--bg-card)',
              border: `1px solid ${feed.reachable ? 'rgba(0,212,255,0.2)' : 'rgba(255,23,68,0.3)'}`,
              borderRadius: 4,
              padding: '20px',
              position: 'relative',
              overflow: 'hidden',
            }}
          >
            <div
              style={{
                position: 'absolute',
                top: 0,
                left: 0,
                right: 0,
                height: 1,
                background: feed.reachable ? 'linear-gradient(90deg, transparent, #00d4ff, transparent)' : 'linear-gradient(90deg, transparent, #ff1744, transparent)',
              }}
            />
            <div className="mb-4 flex items-center justify-between">
              <span className={`font-mono text-[13px] font-semibold tracking-[0.05em] ${feed.reachable ? 'text-cyber-cyan' : 'text-cyber-red'}`}>{feed.display_name.toUpperCase()}</span>
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${feed.reachable ? 'bg-emerald-400' : 'bg-red-500'}`} />
                <span className={`font-mono text-[10px] tracking-[0.1em] ${feed.reachable ? 'text-emerald-400' : 'text-red-400'}`}>{feed.reachable ? 'LIVE' : 'OFFLINE'}</span>
              </div>
            </div>

            {[
              { label: 'REACHABLE', value: feed.reachable ? 'true' : 'false', color: feed.reachable ? 'var(--green)' : 'var(--red)' },
              { label: 'AUTH_VALID', value: feed.auth_valid ? 'true' : 'false', color: feed.auth_valid ? 'var(--green)' : 'var(--orange)' },
              {
                label: 'LATENCY',
                value: feed.latency_ms != null ? `${feed.latency_ms}ms` : '—',
                color: feed.latency_ms == null ? 'var(--text-muted)' : feed.latency_ms < 500 ? 'var(--green)' : feed.latency_ms < 1500 ? '#ffc107' : 'var(--orange)',
              },
              {
                label: 'HTTP_STATUS',
                value: feed.http_status != null ? String(feed.http_status) : '—',
                color: feed.http_status === 200 ? 'var(--green)' : feed.http_status === 429 ? 'var(--orange)' : feed.http_status === 401 ? 'var(--red)' : 'var(--text-muted)',
              },
              {
                label: 'STATUS',
                value: String(feed.status || 'unknown').toUpperCase(),
                color: feed.status === 'live' ? 'var(--green)' : feed.status === 'offline' ? 'var(--red)' : 'var(--text-muted)',
              },
              {
                label: 'LAST_CHECKED',
                value: formatDate(feed.last_checked),
                color: 'var(--text-muted)',
              },
            ].map((row) => (
              <div key={row.label} className="mb-1 flex justify-between font-mono text-[11px]">
                <span className="tracking-[0.05em] text-slate-500">{row.label}</span>
                <span style={{ color: row.color }}>{row.value}</span>
              </div>
            ))}

            {feed.display_name === 'AlienVault OTX' && !feed.auth_valid ? (
              <div className="mt-3 rounded-sm border border-red-500/20 bg-red-500/5 p-2 font-mono text-[10px] text-orange-300">
                [!] API key invalid or missing. Get a free key at otx.alienvault.com then update it below.
              </div>
            ) : null}

            {feed.http_status === 429 ? (
              <div className="mt-3 rounded-sm border border-orange-500/20 bg-orange-500/5 p-2 font-mono text-[10px] text-orange-300">
                [!] RATE_LIMITED - reduce scan frequency or upgrade the API plan.
              </div>
            ) : null}
          </div>
        ))}
      </div>

      {user?.role === 'admin' ? (
        <div className="panel p-5">
          <p className="section-title">Admin Configuration</p>
          <div className="mt-4 grid gap-3">
            <input className="field" placeholder="AlienVault OTX key" value={draft.alienvault_otx} onChange={(event) => setDraft((current) => ({ ...current, alienvault_otx: event.target.value }))} />
            <div className="flex gap-3">
              <button type="button" className="btn-secondary" disabled={testKeyMutation.isPending || !draft.alienvault_otx.trim()} onClick={() => testKeyMutation.mutate()}>
                {testKeyMutation.isPending ? <Spinner /> : null}
                Test Key
              </button>
              {alienVaultTestMessage ? <div className="self-center font-mono text-xs text-slate-400">{alienVaultTestMessage}</div> : null}
            </div>
            <input className="field" placeholder="AbuseIPDB key" value={draft.abuseipdb} onChange={(event) => setDraft((current) => ({ ...current, abuseipdb: event.target.value }))} />
            <input className="field" placeholder="VirusTotal key" value={draft.virustotal} onChange={(event) => setDraft((current) => ({ ...current, virustotal: event.target.value }))} />
            <input className="field" placeholder="URLScan.io key" value={draft.urlscan} onChange={(event) => setDraft((current) => ({ ...current, urlscan: event.target.value }))} />
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
