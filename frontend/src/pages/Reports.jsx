import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import ReactMarkdown from 'react-markdown'
import toast from 'react-hot-toast'
import { Download } from 'lucide-react'
import { generateAriaReport, getAriaReport, getAriaReports } from '../api/aria'
import Spinner from '../components/ui/Spinner'
import EmptyPanel from '../components/shared/EmptyPanel'
import { downloadJson, formatDate } from '../lib/utils'

export default function Reports() {
  const queryClient = useQueryClient()
  const [selectedId, setSelectedId] = useState(null)

  const reportsQuery = useQuery({
    queryKey: ['aria', 'reports'],
    queryFn: getAriaReports,
  })

  const reportQuery = useQuery({
    queryKey: ['aria', 'report', selectedId],
    queryFn: () => getAriaReport(selectedId),
    enabled: !!selectedId,
  })

  const generateMutation = useMutation({
    mutationFn: generateAriaReport,
    onSuccess: (data) => {
      toast.success('Report generated')
      queryClient.invalidateQueries({ queryKey: ['aria', 'reports'] })
      if (data?.id) setSelectedId(data.id)
    },
    onError: (err) => toast.error(err.response?.data?.detail || 'Report generation failed'),
  })

  const reports = reportsQuery.data || []

  return (
    <div className="grid gap-6 xl:grid-cols-[0.8fr_1.2fr]">
      <div className="space-y-4">
        <div className="flex justify-end">
          <button
            type="button"
            className="btn-primary"
            disabled={generateMutation.isPending}
            onClick={() => generateMutation.mutate()}
          >
            {generateMutation.isPending ? <Spinner /> : null}
            Generate report
          </button>
        </div>

        {reportsQuery.isLoading ? (
          <div className="panel flex min-h-[120px] items-center justify-center">
            <Spinner />
          </div>
        ) : reports.length === 0 ? (
          <EmptyPanel
            icon="📊"
            title="No reports yet"
            subtitle='Click "Generate report" to create your first intelligence briefing.'
          />
        ) : (
          reports.map((report) => (
            <button
              key={report.id}
              type="button"
              className={`panel w-full p-5 text-left transition ${selectedId === report.id ? 'ring-1 ring-blue-500/50' : ''}`}
              onClick={() => setSelectedId(report.id)}
            >
              <p className="font-mono text-sm text-slate-50">{report.title}</p>
              <p className="mt-2 text-xs text-slate-500">{formatDate(report.generated_at)}</p>
            </button>
          ))
        )}
      </div>

      <div className="panel-elevated min-h-[600px] p-6">
        {reportQuery.isLoading ? (
          <div className="flex h-full items-center justify-center">
            <Spinner />
          </div>
        ) : reportQuery.data ? (
          <>
            <div className="mb-6 flex items-start justify-between gap-4">
              <div>
                <h2 className="font-mono text-2xl text-slate-50">{reportQuery.data.title}</h2>
                <p className="mt-2 text-sm text-slate-500">
                  {formatDate(reportQuery.data.generated_at)}
                </p>
              </div>
              <button
                type="button"
                className="btn-secondary shrink-0"
                onClick={() => downloadJson(`report-${reportQuery.data.id}.json`, reportQuery.data)}
              >
                <Download className="h-4 w-4" />
                Export
              </button>
            </div>
            <div className="prose prose-invert max-w-none text-sm leading-relaxed">
              <ReactMarkdown>{reportQuery.data.content}</ReactMarkdown>
            </div>
          </>
        ) : (
          <div className="flex h-full items-center justify-center">
            <p className="text-sm text-slate-500">Select a report from the list to view it.</p>
          </div>
        )}
      </div>
    </div>
  )
}
