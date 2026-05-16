import RiskBadge from '../ui/RiskBadge'
import CodeBlock from '../ui/CodeBlock'
import { normalizeRiskLevel, safeArray } from '../../lib/utils'

function extractRows(data) {
  const rows = []
  for (const key of ['urls', 'domains', 'ips', 'hashes']) {
    for (const item of safeArray(data?.results?.[key] || data?.[key])) {
      rows.push({
        ioc: item.value || item.indicator || item.ioc || item.url || item.domain || item.ip || item.hash,
        type: item.type || key.slice(0, -1),
        risk: item.risk_level || item.verdict || item.risk || 'unknown',
        otx: item.pulse_count || item.otx_pulses || item.otx?.pulse_count || 0,
        vt: item.malicious_votes || item.vt_hits || item.virustotal?.malicious || 0,
        abuse: item.abuse_confidence || item.abuseipdb_score || item.abuseipdb?.abuse_confidence || 0,
        source: item.source || item.primary_source || 'multi-source',
        raw: item,
      })
    }
  }

  if (!rows.length && safeArray(data?.indicators).length) {
    return data.indicators.map((item) => ({
      ioc: item.value,
      type: item.type,
      risk: item.risk_level || item.risk || 'unknown',
      otx: item.otx_pulses || 0,
      vt: item.vt_hits || 0,
      abuse: item.abuseipdb_score || 0,
      source: item.source || 'multi-source',
      raw: item,
    }))
  }

  return rows
}

export default function IOCResultTable({ data }) {
  const rows = extractRows(data)

  if (!rows.length) {
    return <div className="panel p-6 text-sm text-slate-400">No IOC rows returned.</div>
  }

  return (
    <div className="space-y-4">
      <div className="overflow-hidden rounded-2xl border border-border">
        <div className="overflow-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-950/80 text-slate-400">
              <tr>
                <th className="px-4 py-3">IOC</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">OTX Pulses</th>
                <th className="px-4 py-3">VT Hits</th>
                <th className="px-4 py-3">AbuseIPDB</th>
                <th className="px-4 py-3">Source</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={`${row.ioc}-${index}`} className="border-t border-border bg-surface/70 align-top">
                  <td className="px-4 py-3 font-mono text-xs text-slate-100">{row.ioc}</td>
                  <td className="px-4 py-3 capitalize text-slate-300">{row.type}</td>
                  <td className="px-4 py-3"><RiskBadge level={normalizeRiskLevel(row.risk)} /></td>
                  <td className="px-4 py-3 text-slate-300">{row.otx}</td>
                  <td className="px-4 py-3 text-slate-300">{row.vt}</td>
                  <td className="px-4 py-3 text-slate-300">{row.abuse}</td>
                  <td className="px-4 py-3 text-slate-300">{row.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="space-y-3">
        {rows.map((row, index) => (
          <details key={`raw-${row.ioc}-${index}`} className="panel p-4">
            <summary className="cursor-pointer text-sm text-slate-200">{row.ioc} raw JSON</summary>
            <div className="mt-4">
              <CodeBlock data={row.raw} />
            </div>
          </details>
        ))}
      </div>
    </div>
  )
}
