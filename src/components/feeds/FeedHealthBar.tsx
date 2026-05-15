"use client";

import Link from "next/link";

import { useLiveFeedPolling } from "@/hooks/useLiveFeedPolling";
import { cn } from "@/lib/utils";

function dotTone(reachable: boolean, authValid: boolean) {
  if (reachable && authValid) return "bg-success shadow-green-glow";
  if (reachable) return "bg-warning";
  return "bg-danger";
}

export function FeedHealthBar({
  apiKey,
  compact = false,
}: {
  apiKey: string;
  compact?: boolean;
}) {
  const { feedData } = useLiveFeedPolling(apiKey);

  return (
    <Link
      href="/feeds/live"
      className={cn(
        "rounded-full border border-white/10 bg-black/40 backdrop-blur transition-all duration-150 hover:border-accent/25 hover:bg-accent/5",
        compact ? "px-3 py-2" : "px-4 py-3",
      )}
    >
      <div className={cn("flex items-center", compact ? "gap-1.5" : "gap-3")}>
        {(feedData?.feeds ?? []).slice(0, 3).map((feed) => (
          <div key={feed.name} className="flex items-center gap-2 font-data text-[11px] uppercase tracking-[0.18em] text-slate-200">
            <span className={`h-2.5 w-2.5 rounded-full ${dotTone(feed.reachable, feed.auth_valid)}`} />
            {compact ? null : feed.display_name}
          </div>
        ))}
      </div>
    </Link>
  );
}
