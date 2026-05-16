import { motion } from 'framer-motion'

export default function FeedDot({ status = 'offline', className = 'h-2.5 w-2.5' }) {
  const color =
    status === 'live' || status === true ? 'bg-green-500 shadow-[0_0_12px_rgba(34,197,94,0.6)]' :
    status === 'degraded' ? 'bg-amber-400 shadow-[0_0_12px_rgba(245,158,11,0.45)]' :
    'bg-red-500'

  return <motion.span animate={status === 'live' || status === true ? { opacity: [0.7, 1, 0.7] } : { opacity: 1 }} transition={{ duration: 2, repeat: Infinity }} className={`${className} rounded-full ${color}`} />
}
