"use client";

import Link from "next/link";

import { useLiveFeedPolling } from "@/hooks/useLiveFeedPolling";

function dotTone(reachable: boolean, authValid: boolean) {
  if (reachable && authValid) return "bg-success shadow-green-glow";
  if (reachable) return "bg-warning";
  return "bg-danger";
}

export function FeedHealthBar({ apiKey }: { apiKey: string }) {
  const { feedData } = useLiveFeedPolling(apiKey);

  return (
    <Link
      href="/feeds/live"
      className="rounded-full border border-white/10 bg-black/40 px-4 py-3 backdrop-blur"
    >
      <div className="flex items-center gap-3">
        {(feedData?.feeds ?? []).slice(0, 3).map((feed) => (
          <div key={feed.name} className="flex items-center gap-2 font-data text-[11px] uppercase tracking-[0.18em] text-slate-200">
            <span className={`h-2.5 w-2.5 rounded-full ${dotTone(feed.reachable, feed.auth_valid)}`} />
            {feed.display_name}
          </div>
        ))}
      </div>
    </Link>
  );
}
