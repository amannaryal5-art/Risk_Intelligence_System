import { motion } from 'framer-motion'
import { scoreColor } from '../../lib/utils'

export default function ScoreRing({ score = 0, size = 120 }) {
  const radius = size / 2 - 10
  const circumference = 2 * Math.PI * radius
  const progress = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference
  const color = scoreColor(score)

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} stroke="#1e293b" strokeWidth="10" fill="none" />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          fill="none"
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: progress }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
          strokeDasharray={circumference}
        />
      </svg>
      <div className="absolute text-center">
        <div className="font-mono text-2xl font-bold text-slate-50">{Math.round(score || 0)}</div>
        <div className="text-[10px] uppercase tracking-[0.25em] text-slate-500">risk</div>
      </div>
    </div>
  )
}
