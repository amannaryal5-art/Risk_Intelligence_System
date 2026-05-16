"use client";

import { Bell, ChevronDown, Menu, MonitorCog, UserCircle2 } from "lucide-react";
import { usePathname } from "next/navigation";
import { useState } from "react";

import { LiveIndicator } from "@/components/layout/LiveIndicator";
import { Badge } from "@/components/shared/Badge";
import { useAssets } from "@/hooks/useAssets";

const pageTitles: Record<string, string> = {
  "/command": "Command Center",
  "/chat": "ARIA AI Chat",
  "/cases": "Cases",
  "/feeds": "Feeds",
  "/campaigns": "Campaigns",
  "/actors": "Actors",
  "/assets": "Assets",
  "/alerts": "Alerts",
  "/reports": "Reports",
};

export function TopBar({ onMobileMenuToggle }: { onMobileMenuToggle: () => void }) {
  const pathname = usePathname();
  const { autoMonitoring, stats } = useAssets();
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <header className="sticky top-0 z-30 -mx-4 border-b border-white/10 bg-[#0a0d12]/90 backdrop-blur-xl lg:-mx-6">
      <div className="flex h-14 items-center gap-3 px-4 lg:px-6">
        <button
          className="rounded-md border border-white/10 p-2 text-slate-300 transition hover:border-white/20 hover:text-white lg:hidden"
          onClick={onMobileMenuToggle}
        >
          <Menu className="h-4 w-4" />
        </button>

        <div className="min-w-0">
          <div className="text-lg font-semibold text-white">{pageTitles[pathname] ?? "ARIA Command"}</div>
        </div>

        <div className="ml-auto flex items-center gap-2 sm:gap-3">
          <LiveIndicator />
          <Badge tone={autoMonitoring ? "green" : "neutral"} className="hidden sm:inline-flex">
            {autoMonitoring ? "Auto-Monitoring Active" : "Monitoring Paused"}
          </Badge>
          <button className="relative rounded-lg border border-white/10 bg-white/5 p-2 text-slate-300 transition hover:border-white/20 hover:text-white">
            <Bell className="h-4 w-4" />
            {stats.unseen_alerts > 0 ? (
              <span className="absolute -right-1 -top-1 min-w-4 rounded-full bg-red-500 px-1 text-center text-[10px] font-semibold text-white">
                {stats.unseen_alerts}
              </span>
            ) : null}
          </button>

          <div className="relative">
            <button
              className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-2.5 py-2 text-sm text-slate-200 transition hover:border-white/20 hover:text-white"
              onClick={() => setMenuOpen((current) => !current)}
            >
              <UserCircle2 className="h-5 w-5" />
              <span className="hidden sm:inline">Analyst</span>
              <ChevronDown className="h-4 w-4" />
            </button>

            {menuOpen ? (
              <div className="absolute right-0 mt-2 w-44 rounded-lg border border-white/10 bg-[#11151c] p-1 shadow-2xl">
                <button className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm text-slate-300 transition hover:bg-white/5 hover:text-white">
                  <MonitorCog className="h-4 w-4" />
                  Workbench
                </button>
                <button className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm text-slate-300 transition hover:bg-white/5 hover:text-white">
                  <UserCircle2 className="h-4 w-4" />
                  Logout
                </button>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </header>
  );
}
