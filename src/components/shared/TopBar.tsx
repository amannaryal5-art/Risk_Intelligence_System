"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import { FeedHealthBar } from "@/components/feeds/FeedHealthBar";
import { PulseDot } from "@/components/shared/PulseDot";
import { useLiveFeedPolling } from "@/hooks/useLiveFeedPolling";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/", label: "Scan" },
  { href: "/feeds/live", label: "Feeds" },
  { href: "/cases", label: "Cases" },
  { href: "/batch", label: "Batch" },
  { href: "/scamcheck", label: "ScamShield" },
];

export function TopBar() {
  const pathname = usePathname();
  const [apiKey, setApiKey] = useState("");
  const { feedData, isConnected } = useLiveFeedPolling(apiKey);

  useEffect(() => {
    setApiKey(window.localStorage.getItem("riskintel_api_key")?.trim() ?? "");
  }, []);

  const latency = useMemo(() => {
    const latencies = (feedData?.feeds ?? []).map((feed) => feed.latency_ms ?? 0).filter(Boolean);
    if (!latencies.length) return "--";
    return String(Math.round(latencies.reduce((sum, current) => sum + current, 0) / latencies.length));
  }, [feedData]);

  return (
    <header className="fixed inset-x-0 top-0 z-40 border-b border-line bg-[rgba(5,10,15,0.82)] backdrop-blur-xl">
      <div className="mx-auto flex min-h-12 max-w-[1600px] flex-wrap items-center gap-3 px-4 py-2 text-white lg:flex-nowrap lg:px-8">
        <Link href="/" className="flex items-center gap-3">
          <div className="font-heading text-lg font-semibold uppercase tracking-[0.08em] text-white">
            RiskIntel v3.0
          </div>
          <div className="inline-flex items-center gap-2 rounded-full border border-success/25 bg-success/10 px-3 py-1 font-data text-[10px] uppercase tracking-[0.22em] text-success">
            <PulseDot color="success" />
            LIVE
          </div>
        </Link>

        <nav className="order-3 flex w-full items-center gap-2 overflow-x-auto lg:order-none lg:w-auto lg:flex-1 lg:justify-center">
          {navItems.map((item) => {
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "border-b-2 border-transparent px-2 py-1 font-data text-xs uppercase tracking-[0.28em] text-muted transition-all duration-150 hover:text-white",
                  active && "border-accent text-accent",
                )}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="ml-auto flex items-center gap-3 font-data text-[11px] uppercase tracking-[0.18em] text-slate-200">
          <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-muted">
            {latency}ms
          </span>
          <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5">
            <PulseDot color={isConnected ? "success" : "warning"} />
            {isConnected ? "LIVE" : "POLL"}
          </span>
          <FeedHealthBar apiKey={apiKey} compact />
        </div>
      </div>
    </header>
  );
}
