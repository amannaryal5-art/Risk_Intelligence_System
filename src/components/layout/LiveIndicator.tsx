"use client";

import { Badge } from "@/components/shared/Badge";
import { useWebSocket } from "@/hooks/useWebSocket";

export function LiveIndicator() {
  const { status } = useWebSocket();

  const tone = status === "connected" ? "green" : status === "reconnecting" ? "yellow" : "red";
  const label = status === "connected" ? "LIVE" : status === "reconnecting" ? "RETRYING" : "OFFLINE";

  return (
    <Badge tone={tone} className="gap-2 px-3 py-1.5">
      <span
        className={`h-2 w-2 rounded-full ${
          status === "connected"
            ? "animate-pulse bg-emerald-400 shadow-[0_0_12px_rgba(34,197,94,0.8)]"
            : status === "reconnecting"
              ? "bg-amber-400 shadow-[0_0_10px_rgba(245,158,11,0.7)]"
              : "bg-red-400 shadow-[0_0_10px_rgba(239,68,68,0.7)]"
        }`}
      />
      {label}
    </Badge>
  );
}
