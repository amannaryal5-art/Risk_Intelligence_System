export function FeedStatusFooter() {
  return (
    <footer className="mt-8 flex flex-col gap-3 rounded-xl border border-accent/15 bg-black/30 px-5 py-4 font-data text-[11px] uppercase tracking-[0.22em] text-muted lg:flex-row lg:items-center lg:justify-between">
      <div>RiskintelAI v3.0</div>
      <div className="text-center">AUTH:ON | FEEDS:LIVE | WSS:CONNECTED</div>
      <div className="text-right">
        /api/v1/analyze | /fusion-scan | /ioc/type/:value
        <span className="ml-2 animate-blink text-accent">_</span>
      </div>
    </footer>
  );
}
