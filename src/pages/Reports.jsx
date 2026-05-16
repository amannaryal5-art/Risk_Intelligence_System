import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import ReactMarkdown from 'react-markdown'
import toast from 'react-hot-toast'
import { generateAriaReport, getAriaReport, getAriaReports } from '../api/aria'
import Spinner from '../components/ui/Spinner'
import { formatDate } from '../lib/utils'

export default function Reports() {
  const [selectedId, setSelectedId] = useState(null)
  const reportsQuery = useQuery({ queryKey: ['aria', 'reports'], queryFn: getAriaReports })
  const reportQuery = useQuery({ queryKey: ['aria', 'report', selectedId], queryFn: () => getAriaReport(selectedId), enabled: !!selectedId })
  const generateMutation = useMutation({
    mutationFn: generateAriaReport,
    onSuccess: () => toast.success('Report generation triggered'),
  })

  return (
    <div className="grid gap-6 xl:grid-cols-[0.8fr_1.2fr]">
      <div className="space-y-4">
        <div className="flex justify-end">
          <button type="button" className="btn-primary" disabled={generateMutation.isPending} onClick={() => generateMutation.mutate()}>Generate Now</button>
        </div>
        {(reportsQuery.data || []).map((report) => (
          <button key={report.id} type="button" className="panel w-full p-5 text-left" onClick={() => setSelectedId(report.id)}>
            <p className="font-mono text-sm text-slate-50">{report.title}</p>
            <p className="mt-2 text-xs text-slate-500">{formatDate(report.generated_at)}</p>
          </button>
        ))}
      </div>
      <div className="panel-elevated min-h-[600px] p-6">
        {reportQuery.isLoading ? <Spinner /> : null}
        {reportQuery.data ? (
          <>
            <h2 className="font-mono text-2xl text-slate-50">{reportQuery.data.title}</h2>
            <p className="mt-2 text-sm text-slate-500">{formatDate(reportQuery.data.generated_at)}</p>
            <div className="prose prose-invert mt-6 max-w-none">
              <ReactMarkdown>{reportQuery.data.content}</ReactMarkdown>
            </div>
          </>
        ) : (
          <p className="text-sm text-slate-400">Select a report to view its full markdown briefing.</p>
        )}
      </div>
    </div>
  )
}
