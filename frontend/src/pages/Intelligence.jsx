import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { useDropzone } from 'react-dropzone'
import client from '../api/client'
import Spinner from '../components/ui/Spinner'
import { useWsStore } from '../store/wsStore'
import { downloadJson } from '../lib/utils'

function detectInputType(value) {
  const input = String(value || '').trim()
  if (!input) return 'AUTO'
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(input)) return 'IP'
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(input)) return 'HASH'
  if (/^https?:\/\//i.test(input) || /^(?:[a-z0-9-]+\.)+[a-z]{2,24}$/i.test(input)) return 'DOMAIN'
  return 'TEXT'
}

export default function Intelligence() {
  const queryClient = useQueryClient()
  const systemScan = useWsStore((state) => state.systemScan)
  const deviceScan = useWsStore((state) => state.deviceScan)
  const [target, setTarget] = useState('')
  const [engines, setEngines] = useState({
    threatIntel: true,
    websiteScan: true,
    hashLookup: true,
    iocMatch: true,
    aiAnalysis: true,
  })

  const sessionQuery = useQuery({
    queryKey: ['intelligence', 'last-session'],
    queryFn: async () => (await client.get('/api/intelligence/last-session')).data,
    retry: false,
    refetchInterval: systemScan.status === 'running' ? 30000 : false,
  })

  const unifiedMutation = useMutation({
    mutationFn: async (payload) => (await client.post('/api/intelligence/unified-scan', payload)).data,
    onError: (error) => toast.error(error.response?.data?.detail || 'Unified scan failed'),
  })

  const systemScanMutation = useMutation({
    mutationFn: async () => (await client.post('/api/intelligence/system-scan')).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['intelligence', 'last-session'] }),
    onError: (error) => toast.error(error.response?.data?.detail || 'System scan failed to start'),
  })

  const deviceSysQuery = useQuery({
    queryKey: ['device', 'sysinfo', 'intelligence'],
    queryFn: async () => (await client.get('/api/device/sysinfo')).data,
    retry: false,
  })

  const deviceScanMutation = useMutation({
    mutationFn: async () => (await client.post('/api/device/scan')).data,
    onSuccess: () => toast.success('Device scan started'),
    onError: (error) => toast.error(error.response?.data?.detail || 'Device scan failed to start'),
  })

  const onDrop = async (files) => {
    const file = files[0]
    if (!file) return
    const buffer = await file.arrayBuffer()
    const digest = await crypto.subtle.digest('SHA-256', buffer)
    const hash = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
    unifiedMutation.mutate({ target: hash, targetType: 'hash', context: file.name, engines })
  }

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ multiple: false, onDrop })
  const detectedType = detectInputType(target)
  const session = sessionQuery.data
  const sessionAssets = session?.full_results?.assets || []
  const correlationMap = session?.correlation_map || {}

  const scoreColor = (score) => (score > 70 ? 'text-red-400' : score >= 30 ? 'text-orange-300' : 'text-emerald-400')

  const manualResult = unifiedMutation.data
  const createCaseMutation = useMutation({
    mutationFn: async () =>
      (
        await client.post('/api/v1/cases', {
          source_type: 'intelligence_manual',
          source_value: manualResult?.target,
          title: `Unified Intelligence: ${manualResult?.target}`,
          severity: (manualResult?.risk_score || 0) > 85 ? 'critical' : (manualResult?.risk_score || 0) > 70 ? 'high' : 'medium',
          status: 'new',
          findings: manualResult || {},
          tags: ['intelligence', 'manual-scan'],
          recommendations: ['Review unified intelligence evidence and triage correlated assets.'],
          ioc_type: manualResult?.targetType,
          ioc_value: manualResult?.target,
          risk_score: Math.round(manualResult?.risk_score || 0),
          scan_result: manualResult || {},
          notes: manualResult?.text_analysis?.summary || manualResult?.verdict,
        })
      ).data,
    onSuccess: () => toast.success('Case created from unified scan'),
  })
  const watchlistMutation = useMutation({
    mutationFn: async () =>
      (
        await client.post('/api/assets', {
          name: manualResult?.target,
          type: manualResult?.targetType === 'domain' ? 'domain' : manualResult?.targetType === 'ip' ? 'ip' : 'domain',
          value: manualResult?.target,
          scan_interval_hours: 6,
        })
      ).data,
    onSuccess: () => toast.success('Added to watchlist'),
  })
  const expandedAssets = useMemo(() => sessionAssets.slice(0, 50), [sessionAssets])

  return (
    <div className="space-y-6">
      <div className="panel-elevated p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="section-title">Asset Scan</p>
            <p className="mt-2 text-sm text-slate-400">{session?.completed_at || session?.triggered_at || 'No session yet'}</p>
          </div>
          <div className={`font-mono text-4xl font-semibold ${scoreColor(session?.overall_risk_score || 0)}`}>
            {Math.round(session?.overall_risk_score || systemScan.summary?.overall_risk_score || 0)}
          </div>
          <div className="grid gap-1 text-sm text-slate-300">
            <span>Assets Scanned: {systemScan.assetsScanned || session?.assets_scanned || 0}</span>
            <span>Threats Found: {systemScan.summary?.threats_found || session?.threats_found || 0}</span>
            <span>Critical: {systemScan.summary?.critical_count || session?.critical_count || 0}</span>
          </div>
          <button type="button" className="btn-secondary" disabled={systemScanMutation.isPending} onClick={() => systemScanMutation.mutate()}>
            Scan Assets
          </button>
          <button type="button" className="btn-secondary" disabled={deviceScanMutation.isPending} onClick={() => deviceScanMutation.mutate()}>
            Scan Device
          </button>
          <button
            type="button"
            className="btn-primary"
            disabled={systemScanMutation.isPending || deviceScanMutation.isPending}
            onClick={() => {
              deviceScanMutation.mutate()
              systemScanMutation.mutate()
            }}
          >
            Scan Everything
          </button>
        </div>
        {systemScan.status === 'running' ? (
          <div className="mt-4">
            <div className="mb-2 flex items-center justify-between text-sm text-cyan-300">
              <span>Scanning {systemScan.currentAsset || 'assets'}...</span>
              <span>{systemScan.progress}%</span>
            </div>
            <div className="h-3 overflow-hidden rounded-full bg-slate-900">
              <div className="scan-sweep h-3 rounded-full bg-cyan-500" style={{ width: `${systemScan.progress}%` }} />
            </div>
          </div>
        ) : null}
      </div>

      <div className="panel p-5">
        <p className="section-title">Unified Manual Scan</p>
        <input className="field mt-4" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="Enter IP, domain, URL, file hash, or paste suspicious text..." />
        <div className="mt-3 flex items-center gap-3 text-sm">
          <span className="rounded-full border border-border bg-slate-950/60 px-3 py-1 text-slate-300">{detectedType}</span>
          {Object.entries(engines).map(([key, value]) => (
            <label key={key} className="flex items-center gap-2 text-slate-300">
              <input type="checkbox" checked={value} onChange={(event) => setEngines((current) => ({ ...current, [key]: event.target.checked }))} />
              {key}
            </label>
          ))}
        </div>
        <button type="button" className="btn-primary mt-4" disabled={!target || unifiedMutation.isPending} onClick={() => unifiedMutation.mutate({ target, targetType: 'auto', engines })}>
          {unifiedMutation.isPending ? <Spinner /> : null}
          Scan
        </button>
      </div>

      {manualResult ? (
        <div className="panel-elevated p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="font-mono text-2xl text-slate-50">Risk Score: {manualResult.risk_score}/100</p>
              <p className="mt-2 text-sm text-slate-400">Target: {manualResult.target} | Type: {manualResult.targetType} | Scanned: {manualResult.scanned_at}</p>
            </div>
            <span className={`rounded-full px-3 py-1 text-xs font-semibold ${manualResult.risk_score > 70 ? 'bg-red-950/40 text-red-300' : manualResult.risk_score >= 30 ? 'bg-orange-950/40 text-orange-300' : 'bg-emerald-950/40 text-emerald-300'}`}>
              {manualResult.verdict}
            </span>
          </div>
          <div className="mt-6 grid gap-4 xl:grid-cols-2">
            <UnifiedSection title="Threat Intel" lines={[
              `AbuseIPDB: ${(manualResult.summary?.abuseipdb?.abuse_confidence ?? manualResult.summary?.abuseipdb?.abuseConfidence ?? 0) || 0}`,
              `AlienVault OTX: ${(manualResult.summary?.otx?.pulse_count ?? 0) || 0} pulses matched`,
            ]} />
            <UnifiedSection title="Website Scan" lines={[
              `URLScan.io: ${manualResult.summary?.urlscan_verdict || manualResult.website_scan?.error || 'no verdict'}`,
              `VirusTotal: ${manualResult.summary?.virustotal?.malicious_votes || 0} malicious`,
            ]} />
            <UnifiedSection title="IOC Correlation" lines={[
              `Found in ${manualResult.ioc_correlation?.match_count || 0} other monitored assets / IOC records`,
            ]} />
            <UnifiedSection title="AI Analysis" lines={[
              manualResult.text_analysis?.summary || manualResult.text_analysis?.result?.summary || 'No AI analysis summary returned.',
            ]} />
          </div>
          <div className="mt-6 flex flex-wrap gap-3">
            <button type="button" className="btn-secondary" disabled={createCaseMutation.isPending} onClick={() => createCaseMutation.mutate()}>
              {createCaseMutation.isPending ? <Spinner /> : null}
              Create Case
            </button>
            <button type="button" className="btn-secondary" disabled={watchlistMutation.isPending || !['domain', 'ip'].includes(String(manualResult.targetType))} onClick={() => watchlistMutation.mutate()}>
              {watchlistMutation.isPending ? <Spinner /> : null}
              Add to Watchlist
            </button>
            <button type="button" className="btn-primary" onClick={() => downloadJson('unified-intelligence-result.json', manualResult)}>
              Export Report
            </button>
          </div>
        </div>
      ) : null}

      <div className="panel p-5">
        <div className="flex items-center justify-between gap-4">
          <p className="section-title">System Scan Results</p>
          <button type="button" className="btn-secondary" onClick={() => toast.success(Object.keys(correlationMap).length ? 'Correlation map loaded below' : 'No multi-asset IOC overlap found')}>
            View Correlation Map
          </button>
        </div>
        <div className="mt-4 overflow-hidden rounded-2xl border border-border">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-950/80 text-slate-400">
              <tr>
                <th className="px-4 py-3">Asset</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Risk Score</th>
                <th className="px-4 py-3">Threats Found</th>
                <th className="px-4 py-3">IOC Matches</th>
                <th className="px-4 py-3">Verdict</th>
              </tr>
            </thead>
            <tbody>
              {expandedAssets.map((item, index) => (
                <tr key={`${item.target}-${index}`} className={`border-t border-border ${item.risk_score > 70 ? 'bg-red-950/10' : item.risk_score > 30 ? 'bg-orange-950/10' : 'bg-emerald-950/10'}`}>
                  <td className="px-4 py-3 text-slate-200">{item.asset?.label || item.target}</td>
                  <td className="px-4 py-3 text-slate-300">{item.targetType}</td>
                  <td className="px-4 py-3 text-slate-300">{item.risk_score}</td>
                  <td className="px-4 py-3 text-slate-300">{item.risk_score > 55 ? 1 : 0}</td>
                  <td className="px-4 py-3 text-slate-300">{item.ioc_correlation?.match_count || 0}</td>
                  <td className="px-4 py-3 text-slate-300">{item.verdict}</td>
                </tr>
              ))}
              {!expandedAssets.length ? (
                <tr>
                  <td colSpan="6" className="px-4 py-8 text-center text-slate-500">No system scan session results yet.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        {Object.keys(correlationMap).length ? (
          <div className="mt-4 rounded-2xl border border-border bg-slate-950/50 p-4 text-sm text-slate-300">
            {Object.entries(correlationMap).map(([ioc, assets]) => (
              <div key={ioc} className="mb-2">
                <span className="font-mono text-cyan-300">{ioc}</span>: {assets.join(', ')}
              </div>
            ))}
          </div>
        ) : null}
      </div>

      <div {...getRootProps()} className={`panel p-8 text-center ${isDragActive ? 'border-cyan-500 bg-cyan-500/5' : ''}`}>
        <input {...getInputProps()} />
        <p className="font-mono text-lg text-slate-100">Drop file for malware analysis</p>
        <p className="mt-2 text-sm text-slate-400">A SHA-256 hash will be derived client-side and scanned through the unified intelligence engine.</p>
      </div>
    </div>
  )
}

function UnifiedSection({ title, lines }) {
  return (
    <div className="rounded-2xl border border-border bg-slate-950/60 p-4">
      <p className="section-title">{title}</p>
      <div className="mt-3 space-y-2 text-sm text-slate-300">
        {lines.map((line, index) => <p key={`${title}-${index}`}>{line}</p>)}
      </div>
    </div>
  )
}
