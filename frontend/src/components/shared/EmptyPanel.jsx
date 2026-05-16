export default function EmptyPanel({ icon = '📭', title = 'Nothing here yet', subtitle = '' }) {
  return (
    <div className="panel flex min-h-[220px] flex-col items-center justify-center gap-3 p-8 text-center">
      <span className="text-4xl">{icon}</span>
      <p className="font-mono text-slate-200">{title}</p>
      {subtitle ? <p className="text-sm text-slate-500">{subtitle}</p> : null}
    </div>
  )
}
