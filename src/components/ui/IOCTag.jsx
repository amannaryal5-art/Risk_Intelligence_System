import { Copy } from 'lucide-react'
import toast from 'react-hot-toast'
import { copyText, cn } from '../../lib/utils'

const tones = {
  domain: 'border-blue-700/70 bg-blue-950/40 text-blue-300',
  ip: 'border-violet-700/70 bg-violet-950/40 text-violet-300',
  url: 'border-cyan-700/70 bg-cyan-950/40 text-cyan-300',
  hash: 'border-slate-600 bg-slate-900 text-slate-300',
}

export default function IOCTag({ type = 'hash', value, className }) {
  const key = type.startsWith('hash') ? 'hash' : type

  return (
    <button
      type="button"
      onClick={async () => {
        await copyText(value)
        toast.success('Copied IOC')
      }}
      className={cn('inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs', tones[key] || tones.hash, className)}
    >
      <span className="uppercase">{type}</span>
      <span className="max-w-[220px] truncate">{value}</span>
      <Copy className="h-3.5 w-3.5" />
    </button>
  )
}
