import { useEffect, useRef } from 'react'

export default function TerminalOutput({ lines = [], autoScroll = true, height = 'h-80', className = '' }) {
  const scrollRef = useRef(null)

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [lines, autoScroll])

  return (
    <div className={`hacker-panel flex flex-col ${height} ${className}`}>
      <div className="flex items-center gap-2 border-b border-cyber-cyan/30 bg-cyber-cyan/5 px-4 py-2">
        <div className="h-2 w-2 rounded-full bg-cyber-red/80 shadow-[0_0_5px_rgba(255,23,68,0.5)]" />
        <div className="h-2 w-2 rounded-full bg-yellow-500/80 shadow-[0_0_5px_rgba(234,179,8,0.5)]" />
        <div className="h-2 w-2 rounded-full bg-cyber-green/80 shadow-[0_0_5px_rgba(0,230,118,0.5)]" />
        <span className="ml-2 text-[10px] font-mono text-cyber-cyan/50">bash /usr/bin/crie_sys_log</span>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-auto p-4 font-mono text-xs">
        {lines.length === 0 ? (
          <p className="text-cyber-cyan/40">Waiting for data...</p>
        ) : (
          lines.map((line, idx) => (
            <div key={idx} className="mb-1 leading-relaxed">
              <span className="text-cyber-cyan/50 mr-2">{'>'}</span>
              <span className={line.includes('ERROR') ? 'text-cyber-red' : line.includes('WARN') ? 'text-yellow-400' : 'text-cyber-cyan/90'}>
                {line}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
