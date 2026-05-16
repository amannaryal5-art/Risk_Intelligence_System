import { useWsStore } from '../../store/wsStore'
import FeedDot from '../ui/FeedDot'

export default function FeedStatusBar() {
  const { feedStatus, connected } = useWsStore()
  const feeds = feedStatus?.feeds || []

  return (
    <div className="fixed bottom-0 left-0 right-0 z-30 border-t border-border bg-[#070b12]/95 backdrop-blur">
      <div className="mx-auto flex max-w-[1600px] items-center justify-between gap-4 px-4 py-2 text-xs text-slate-400">
        <div className="flex flex-wrap items-center gap-4">
          {feeds.map((feed) => {
            const status = feed.auth_valid ? 'live' : feed.reachable ? 'degraded' : 'offline'
            return (
              <div key={feed.name} title={feed.display_name} className="flex items-center gap-2">
                <FeedDot status={status} />
                <span>{feed.display_name}</span>
              </div>
            )
          })}
        </div>
        <div className="flex items-center gap-2">
          <FeedDot status={connected ? 'live' : 'offline'} className="h-2 w-2" />
          <span>{connected ? 'WS connected' : 'WS reconnecting'}</span>
        </div>
      </div>
    </div>
  )
}
