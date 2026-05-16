import { useRef, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Activity } from 'lucide-react'
import { fusionScan } from '../api/analysis'
import AnalyzeResultCard from '../components/shared/AnalyzeResultCard'
import Spinner from '../components/ui/Spinner'

export default function FusionScan() {
  const [form, setForm] = useState({
    text: '',
    website_url: '',
    max_pages: 80,
    max_depth: 3,
    include_external: false,
    exhaustive: true,
  })
  const [elapsed, setElapsed] = useState(0)
  const timerRef = useRef(null)

  const mutation = useMutation({
    mutationFn: () => fusionScan(form),
    onMutate: () => {
      setElapsed(0)
      timerRef.current = window.setInterval(() => setElapsed((v) => v + 1), 1000)
    },
    onSettled: () => {
      if (timerRef.current) {
        window.clearInterval(timerRef.current)
        timerRef.current = null
      }
    },
    onError: (err) => toast.error(err.response?.data?.detail || 'Fusion scan failed'),
  })

  const canRun = form.text.trim().length > 0 || form.website_url.trim().length > 0

  return (
    <div className="space-y-6">
      <div className="panel p-5">
        <div className="mb-4 flex items-center gap-3">
          <Activity className="h-5 w-5 text-cyan-400" />
          <p className="font-mono text-lg text-slate-50">Fusion Scan</p>
          <span className="text-sm text-slate-500">
            Combines text analysis + website intelligence + live IOC feeds into one pass
          </span>
        </div>

        <div className="space-y-4">
          <textarea
            className="field min-h-32"
            placeholder="Paste suspicious text, email body, or phishing content…"
            value={form.text}
            onChange={(e) => setForm((f) => ({ ...f, text: e.target.value }))}
          />
          <input
            className="field"
            placeholder="Website URL to scan (optional) — e.g. https://suspicious-site.com"
            value={form.website_url}
            onChange={(e) => setForm((f) => ({ ...f, website_url: e.target.value }))}
          />

          <div className="grid gap-4 md:grid-cols-3">
            <div>
              <label className="mb-1 block text-xs text-slate-400">Max pages</label>
              <input
                className="field"
                type="number"
                min="1"
                max="500"
                value={form.max_pages}
                onChange={(e) => setForm((f) => ({ ...f, max_pages: Number(e.target.value) }))}
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-slate-400">Max depth</label>
              <input
                className="field"
                type="number"
                min="0"
                max="8"
                value={form.max_depth}
                onChange={(e) => setForm((f) => ({ ...f, max_depth: Number(e.target.value) }))}
              />
            </div>
            <div className="flex flex-col justify-end gap-3 pb-1">
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={form.include_external}
                  onChange={(e) => setForm((f) => ({ ...f, include_external: e.target.checked }))}
                />
                Include external links
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={form.exhaustive}
                  onChange={(e) => setForm((f) => ({ ...f, exhaustive: e.target.checked }))}
                />
                Exhaustive crawl
              </label>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <button
              type="button"
              className="btn-primary"
              disabled={!canRun || mutation.isPending}
              onClick={() => mutation.mutate()}
            >
              {mutation.isPending ? <Spinner /> : null}
              {mutation.isPending ? `Running… ${elapsed}s` : 'Run Fusion Scan'}
            </button>
            {mutation.isPending ? (
              <p className="text-xs text-slate-500">
                Crawling + analyzing — this may take 20–90 seconds
              </p>
            ) : null}
          </div>
        </div>
      </div>

      {mutation.data ? (
        <div className="panel-elevated p-6">
          <p className="section-title mb-4">Fusion Scan Result</p>
          <AnalyzeResultCard result={mutation.data} />
        </div>
      ) : null}
    </div>
  )
}
