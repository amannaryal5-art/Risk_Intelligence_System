"use client";

import { useWebSocket } from "@/hooks/useWebSocket";

export function ReconnectModal() {
  const { status, reconnectIn, queuedActions } = useWebSocket();

  if (status !== "reconnecting") return null;

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-black/60 backdrop-blur-md">
      <div className="panel panel-grid w-full max-w-md p-6">
        <div className="eyebrow">Connection Lost</div>
        <h2 className="mt-3 text-2xl font-semibold text-white">Retrying live control plane</h2>
        <p className="mt-3 text-sm text-slate-300">Reconnecting to backend in {reconnectIn}s.</p>
        <p className="mt-2 font-mono text-sm text-slate-400">Queued analyst actions: {queuedActions}</p>
      </div>
    </div>
  );
}
