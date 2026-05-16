import { useEffect, useMemo, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Download, Plus, Trash2 } from 'lucide-react'
import { analyzeBatch, analyzeText, fusionScan, scamCheck } from '../api/analysis'
import { createCaseFromAnalysis } from '../api/cases'
import AnalyzeResultCard from '../components/shared/AnalyzeResultCard'
import Spinner from '../components/ui/Spinner'
import { downloadCsv, normalizeRiskLevel, pushHistory } from '../lib/utils'
import { useAuthStore } from '../store/authStore'

const tabs = ['Text Analysis', 'Batch Analysis', 'Scam Check', 'Fusion Scan']
const scamTypes = ['email', 'sms', 'whatsapp', 'social_media', 'url', 'phone', 'document', 'other']
const templates = {
  'Romance Fraud Sample': 'I met someone overseas who says they love me and needs urgent money for customs clearance.',
  'Phishing Email Sample': 'Your account has been suspended. Click here immediately to verify your credentials and avoid service interruption.',
  'Tech Support Scam Sample': 'Your computer is infected. Call Microsoft support now and grant remote access to remove the virus.',
}

export default function Analyze({ initialTab = 'Text Analysis' }) {
  const [activeTab, setActiveTab] = useState(initialTab)
  const [text, setText] = useState('')
  const [batchTexts, setBatchTexts] = useState([''])
  const [scamInput, setScamInput] = useState('')
  const [scamType, setScamType] = useState('email')
  const [fusionState, setFusionState] = useState({ text: '', website_url: '', max_pages: 80, max_depth: 3, include_external: false, exhaustive: true })
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [caseTitle, setCaseTitle] = useState('')
  const [caseModal, setCaseModal] = useState(false)
  const user = useAuthStore((state) => state.user)

  useEffect(() => {
    setActiveTab(initialTab)
  }, [initialTab])

  const textAnalysis = useMutation({
    mutationFn: () => analyzeText({ text }),
    onSuccess: (data) => {
      pushHistory('crie-analysis-history', data, 20)
      setCaseTitle(`Text risk case — ${new Date().toLocaleString()}`)
    },
    onError: (error) => toast.error(error.response?.data?.detail || 'Text analysis failed'),
  })

  const batchAnalysis = useMutation({
    mutationFn: () => analyzeBatch({ texts: batchTexts.filter(Boolean) }),
    onError: (error) => toast.error(error.response?.data?.detail || 'Batch analysis failed'),
  })

  const scamMutation = useMutation({
    mutationFn: () => scamCheck({ input: scamInput, detectedType: scamType }),
    onError: (error) => toast.error(error.response?.data?.detail || 'Scam check failed'),
  })

  const fusionMutation = useMutation({
    mutationFn: () => fusionScan(fusionState),
    onError: (error) => toast.error(error.response?.data?.detail || 'Fusion scan failed'),
  })

  const createCaseMutation = useMutation({
    mutationFn: () => createCaseFromAnalysis({ title: caseTitle, text, tags: [normalizeRiskLevel(textAnalysis.data?.risk_level)], assigned_to: user?.username }),
    onSuccess: () => {
      setCaseModal(false)
      toast.success('Case created from analysis')
    },
    onError: (error) => toast.error(error.response?.data?.detail || 'Case creation failed'),
  })

  const batchRows = useMemo(() => batchAnalysis.data?.results || [], [batchAnalysis.data])

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-3">
        {tabs.map((tab) => (
          <button key={tab} type="button" className={activeTab === tab ? 'btn-primary' : 'btn-secondary'} onClick={() => setActiveTab(tab)}>
            {tab}
          </button>
        ))}
      </div>

      {activeTab === 'Text Analysis' ? (
        <div className="space-y-6">
          <div className="panel p-5">
            <div className="flex flex-wrap gap-2">
              {Object.entries(templates).map(([label, value]) => (
                <button key={label} type="button" className="btn-secondary" onClick={() => setText(value)}>{label}</button>
              ))}
            </div>
            <textarea className="field mt-4 min-h-48" value={text} onChange={(event) => setText(event.target.value)} placeholder="Paste suspicious text, email, message, or transcript…" />
            <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
              <span>{text.length} characters</span>
              <button type="button" className="btn-primary" disabled={!text || textAnalysis.isPending} onClick={() => textAnalysis.mutate()}>
                {textAnalysis.isPending ? <Spinner /> : null}
                Analyze
              </button>
            </div>
          </div>
          <AnalyzeResultCard result={textAnalysis.data} onCreateCase={() => setCaseModal(true)} />
        </div>
      ) : null}

      {activeTab === 'Batch Analysis' ? (
        <div className="space-y-6">
          <div className="panel p-5">
            <div className="space-y-3">
              {batchTexts.map((value, index) => (
                <div key={index} className="flex gap-3">
                  <textarea className="field min-h-24" value={value} onChange={(event) => setBatchTexts((current) => current.map((item, i) => i === index ? event.target.value : item))} />
                  <button type="button" className="btn-secondary self-start" onClick={() => setBatchTexts((current) => current.filter((_, i) => i !== index))} disabled={batchTexts.length === 1}>
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
            <div className="mt-4 flex flex-wrap gap-3">
              <button type="button" className="btn-secondary" onClick={() => batchTexts.length < 100 && setBatchTexts((current) => [...current, ''])}>
                <Plus className="h-4 w-4" />
                Add Row
              </button>
              <button type="button" className="btn-primary" disabled={!batchTexts.filter(Boolean).length || batchAnalysis.isPending} onClick={() => batchAnalysis.mutate()}>
                {batchAnalysis.isPending ? <Spinner /> : null}
                Analyze Batch
              </button>
              <button type="button" className="btn-secondary" disabled={!batchRows.length} onClick={() => downloadCsv('batch-analysis.csv', [['Text', 'Score', 'Risk'], ...batchRows.map((row) => [row.text || '', row.score || 0, row.risk_level || 'unknown'])])}>
                <Download className="h-4 w-4" />
                Export CSV
              </button>
            </div>
          </div>

          {batchRows.length ? (
            <div className="overflow-hidden rounded-2xl border border-border">
              <table className="min-w-full text-left text-sm">
                <thead className="bg-slate-950/80 text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Text</th>
                    <th className="px-4 py-3">Score</th>
                    <th className="px-4 py-3">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {batchRows.map((row, index) => (
                    <tr key={index} className="border-t border-border bg-surface/70">
                      <td className="px-4 py-3 text-slate-300">{row.text || batchTexts[index]}</td>
                      <td className="px-4 py-3 font-mono text-slate-100">{row.score || 0}</td>
                      <td className="px-4 py-3 text-slate-300">{row.risk_level || 'unknown'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      ) : null}

      {activeTab === 'Scam Check' ? (
        <div className="space-y-6">
          <div className="panel p-5">
            <textarea className="field min-h-40" value={scamInput} onChange={(event) => setScamInput(event.target.value)} placeholder="Paste message, phone script, or document text" />
            <div className="mt-4 grid gap-3 md:grid-cols-[1fr_auto]">
              <select className="field" value={scamType} onChange={(event) => setScamType(event.target.value)}>
                {scamTypes.map((type) => <option key={type}>{type}</option>)}
              </select>
              <button type="button" className="btn-primary" disabled={!scamInput || scamMutation.isPending} onClick={() => scamMutation.mutate()}>
                {scamMutation.isPending ? <Spinner /> : null}
                Run Scam Check
              </button>
            </div>
          </div>
          <AnalyzeResultCard result={scamMutation.data} title="Scam Check Result" />
        </div>
      ) : null}

      {activeTab === 'Fusion Scan' ? (
        <div className="space-y-6">
          <div className="panel p-5">
            <textarea className="field min-h-36" value={fusionState.text} onChange={(event) => setFusionState((current) => ({ ...current, text: event.target.value }))} placeholder="Optional text evidence" />
            <input className="field mt-3" value={fusionState.website_url} onChange={(event) => setFusionState((current) => ({ ...current, website_url: event.target.value }))} placeholder="Optional website URL" />
            <button type="button" className="mt-4 text-sm text-cyan-400" onClick={() => setShowAdvanced((value) => !value)}>Advanced options</button>
            {showAdvanced ? (
              <div className="mt-4 grid gap-3 md:grid-cols-2">
                <input className="field" type="number" value={fusionState.max_pages} onChange={(event) => setFusionState((current) => ({ ...current, max_pages: Number(event.target.value) }))} />
                <input className="field" type="number" value={fusionState.max_depth} onChange={(event) => setFusionState((current) => ({ ...current, max_depth: Number(event.target.value) }))} />
                <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={fusionState.include_external} onChange={(event) => setFusionState((current) => ({ ...current, include_external: event.target.checked }))} />Include external links</label>
                <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={fusionState.exhaustive} onChange={(event) => setFusionState((current) => ({ ...current, exhaustive: event.target.checked }))} />Exhaustive mode</label>
              </div>
            ) : null}
            <button type="button" className="btn-primary mt-4" disabled={(!fusionState.text && !fusionState.website_url) || fusionMutation.isPending} onClick={() => fusionMutation.mutate()}>
              {fusionMutation.isPending ? <Spinner /> : null}
              Run Fusion Scan
            </button>
          </div>
          <AnalyzeResultCard result={fusionMutation.data} title="Fusion Scan Result" />
        </div>
      ) : null}

      {caseModal ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="panel-elevated w-full max-w-xl p-6">
            <h3 className="font-mono text-xl text-slate-50">Create case from analysis</h3>
            <input className="field mt-4" value={caseTitle} onChange={(event) => setCaseTitle(event.target.value)} />
            <div className="mt-4 flex justify-end gap-3">
              <button type="button" className="btn-secondary" onClick={() => setCaseModal(false)}>Cancel</button>
              <button type="button" className="btn-primary" disabled={!caseTitle || createCaseMutation.isPending} onClick={() => createCaseMutation.mutate()}>
                {createCaseMutation.isPending ? <Spinner /> : null}
                Create Case
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}
