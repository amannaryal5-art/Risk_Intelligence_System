import { motion } from 'framer-motion'
import { Download, FolderPlus } from 'lucide-react'
import RiskBadge from '../ui/RiskBadge'
import ScoreRing from '../ui/ScoreRing'
import IOCTag from '../ui/IOCTag'
import { downloadJson, normalizeRiskLevel, safeArray } from '../../lib/utils'

export default function AnalyzeResultCard({ result, title = 'Analysis Result', onCreateCase }) {
  if (!result) return null

  const riskLevel = normalizeRiskLevel(result.risk_level || result.verdict || result.posture_state)
  const score = result.score ?? result.risk_score ?? result.posture_score ?? 0
  const topSignals =
    safeArray(result.top_signals).length ? result.top_signals :
    safeArray(result.red_flags).length ? result.red_flags :
    safeArray(result.suspicious_signals)

  const iocItems = [
    ...safeArray(result?.ioc_intelligence?.urls).map((value) => ['url', value]),
    ...safeArray(result?.ioc_intelligence?.domains).map((value) => ['domain', value]),
    ...safeArray(result?.ioc_intelligence?.ips).map((value) => ['ip', value]),
    ...safeArray(result?.ioc_intelligence?.hashes).map((value) => ['hash', value]),
  ]

  return (
    <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} className="panel-elevated p-6">
      <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-6">
          <ScoreRing score={score} size={140} />
          <div>
            <p className="section-title">{title}</p>
            <div className="mt-3">
              <RiskBadge level={riskLevel} />
            </div>
            <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
              {result.verdict || result.summary || result.reasoning || result.posture_summary || 'Analysis completed.'}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-3">
          {onCreateCase ? (
            <button type="button" className="btn-secondary" onClick={onCreateCase}>
              <FolderPlus className="h-4 w-4" />
              Create Case from This
            </button>
          ) : null}
          <button type="button" className="btn-primary" onClick={() => downloadJson('analysis-result.json', result)}>
            <Download className="h-4 w-4" />
            Export JSON
          </button>
        </div>
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <div className="rounded-2xl border border-border bg-slate-950/60 p-4">
          <p className="section-title">Top Signals</p>
          <ul className="mt-4 space-y-3 text-sm text-slate-300">
            {topSignals.length ? topSignals.map((signal, index) => <li key={`${signal}-${index}`}>• {signal}</li>) : <li>No major red flags returned.</li>}
          </ul>
        </div>
        <div className="rounded-2xl border border-border bg-slate-950/60 p-4">
          <p className="section-title">Recommendations</p>
          <ul className="mt-4 space-y-3 text-sm text-slate-300">
            {safeArray(result.recommendations).length ? safeArray(result.recommendations).map((item, index) => <li key={`${item}-${index}`}>• {item}</li>) : <li>No recommendations returned.</li>}
          </ul>
        </div>
      </div>

      <details className="mt-6 rounded-2xl border border-border bg-slate-950/60 p-4">
        <summary className="cursor-pointer text-sm font-medium text-slate-100">IOC Intelligence</summary>
        <div className="mt-4 flex flex-wrap gap-2">
          {iocItems.length ? iocItems.map(([type, value]) => <IOCTag key={`${type}-${value}`} type={type} value={value} />) : <p className="text-sm text-slate-400">No IOC extraction returned for this result.</p>}
        </div>
      </details>
    </motion.div>
  )
}
