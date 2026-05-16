import { motion } from 'framer-motion'
import { cn, normalizeRiskLevel, RISK_COLORS } from '../../lib/utils'

export default function RiskBadge({ level = 'unknown', className }) {
  const key = normalizeRiskLevel(level)
  const tone = RISK_COLORS[key]

  return (
    <motion.span
      initial={{ scale: 0.92, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      className={cn('inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wide', tone.bg, tone.text, tone.border, className)}
    >
      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: tone.dot }} />
      {key}
    </motion.span>
  )
}
