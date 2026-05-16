import { Copy } from 'lucide-react'
import toast from 'react-hot-toast'
import { copyText } from '../../lib/utils'

export default function CodeBlock({ data }) {
  const value = typeof data === 'string' ? data : JSON.stringify(data, null, 2)

  return (
    <div className="overflow-hidden rounded-2xl border border-border bg-slate-950">
      <div className="flex items-center justify-between border-b border-border px-4 py-2 text-xs text-slate-400">
        <span>JSON payload</span>
        <button
          type="button"
          className="btn-secondary px-2 py-1 text-xs"
          onClick={async () => {
            await copyText(value)
            toast.success('Copied JSON')
          }}
        >
          <Copy className="h-3.5 w-3.5" />
          Copy
        </button>
      </div>
      <pre className="max-h-[420px] overflow-auto p-4 text-xs text-slate-200">{value}</pre>
    </div>
  )
}
