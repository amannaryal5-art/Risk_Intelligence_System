export default function CaseBadge({ status = 'new' }) {
  const tones = {
    new: 'border-cyan-700/70 bg-cyan-950/40 text-cyan-300',
    triaged: 'border-amber-700/70 bg-amber-950/40 text-amber-300',
    escalated: 'border-orange-700/70 bg-orange-950/40 text-orange-300',
    closed: 'border-emerald-700/70 bg-emerald-950/40 text-emerald-300',
  }

  return <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-medium capitalize ${tones[status] || tones.new}`}>{status}</span>
}
