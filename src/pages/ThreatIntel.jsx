import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { getThreatIntel } from '../api/threatIntel'
import { extractIOCs } from '../lib/utils'
import IOCResultTable from '../components/shared/IOCResultTable'
import QuickIOCLookup from '../components/shared/QuickIOCLookup'
import Spinner from '../components/ui/Spinner'

function parseList(value) {
  return value.split(',').map((item) => item.trim()).filter(Boolean)
}

export default function ThreatIntel() {
  const [rawText, setRawText] = useState('')
  const [manual, setManual] = useState({ urls: '', domains: '', ips: '', hashes: '' })
  const [liveFeeds, setLiveFeeds] = useState(true)
  const extracted = extractIOCs(rawText)

  const scan = useMutation({
    mutationFn: () => getThreatIntel({
      text: rawText || undefined,
      urls: [...new Set([...extracted.urls, ...parseList(manual.urls)])],
      domains: [...new Set([...extracted.domains, ...parseList(manual.domains)])],
      ips: [...new Set([...extracted.ips, ...parseList(manual.ips)])],
      hashes: [...new Set([...extracted.hashes, ...parseList(manual.hashes)])],
      live_feeds: liveFeeds,
    }),
    onError: (error) => toast.error(error.response?.data?.detail || 'Threat intel scan failed'),
  })

  return (
    <div className="space-y-6">
      <div className="grid gap-6 xl:grid-cols-2">
        <div className="panel p-5">
          <p className="section-title">IOC Input</p>
          <textarea className="field mt-4 min-h-40" value={rawText} onChange={(event) => setRawText(event.target.value)} placeholder="Paste text to auto-extract domains, IPs, URLs, and hashes" />
          <div className="mt-4 grid gap-3">
            <input className="field" placeholder="Manual URLs, comma separated" value={manual.urls} onChange={(event) => setManual((current) => ({ ...current, urls: event.target.value }))} />
            <input className="field" placeholder="Manual domains, comma separated" value={manual.domains} onChange={(event) => setManual((current) => ({ ...current, domains: event.target.value }))} />
            <input className="field" placeholder="Manual IPs, comma separated" value={manual.ips} onChange={(event) => setManual((current) => ({ ...current, ips: event.target.value }))} />
            <input className="field" placeholder="Manual hashes, comma separated" value={manual.hashes} onChange={(event) => setManual((current) => ({ ...current, hashes: event.target.value }))} />
          </div>
          <div className="mt-4 flex items-center justify-between">
            <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={liveFeeds} onChange={(event) => setLiveFeeds(event.target.checked)} />Use live feeds</label>
            <button type="button" className="btn-primary" disabled={scan.isPending} onClick={() => scan.mutate()}>
              {scan.isPending ? <Spinner /> : null}
              Analyze IOCs
            </button>
          </div>
        </div>
        <QuickIOCLookup />
      </div>

      <div className="panel p-5">
        <p className="section-title">Results</p>
        <div className="mt-4">
          <IOCResultTable data={scan.data} />
        </div>
      </div>
    </div>
  )
}
