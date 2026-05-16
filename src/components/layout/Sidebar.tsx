"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  AlertTriangle,
  Briefcase,
  ChevronLeft,
  FileText,
  FolderKanban,
  LayoutDashboard,
  MessageSquareText,
  RadioTower,
  Shield,
  Sparkles,
  Users,
  Waypoints,
  X,
} from "lucide-react";

import { Badge } from "@/components/shared/Badge";
import { useAssets } from "@/hooks/useAssets";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/command", label: "Command", icon: LayoutDashboard },
  { href: "/chat", label: "Chat", icon: MessageSquareText },
  { href: "/cases", label: "Cases", icon: Briefcase },
  { href: "/feeds", label: "Feeds", icon: RadioTower },
  { href: "/campaigns", label: "Campaigns", icon: FolderKanban },
  { href: "/actors", label: "Actors", icon: Users },
  { href: "/assets", label: "Assets", icon: Shield },
  { href: "/alerts", label: "Alerts", icon: AlertTriangle },
  { href: "/reports", label: "Reports", icon: FileText },
];

const quickStats = [
  { key: "total", label: "Assets", tone: "blue" as const },
  { key: "critical", label: "Critical", tone: "red" as const },
  { key: "high", label: "High", tone: "yellow" as const },
  { key: "clean", label: "Clean", tone: "green" as const },
];

export function Sidebar({
  collapsed,
  mobileOpen,
  onCollapseToggle,
  onMobileClose,
}: {
  collapsed: boolean;
  mobileOpen: boolean;
  onCollapseToggle: () => void;
  onMobileClose: () => void;
}) {
  const pathname = usePathname();
  const { stats } = useAssets();

  return (
    <>
      {mobileOpen ? <button className="fixed inset-0 z-40 bg-black/50 lg:hidden" onClick={onMobileClose} /> : null}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex border-r border-white/10 bg-[#0e1116]/95 backdrop-blur-xl transition-all duration-300",
          collapsed ? "w-[60px]" : "w-[260px]",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
          "lg:translate-x-0",
        )}
      >
        <div className="flex w-full flex-col">
          <div className="flex h-14 items-center justify-between border-b border-white/10 px-4">
            <div className={cn("min-w-0", collapsed && "hidden")}>
              <div className="flex items-center gap-2">
                <span className="rounded-md bg-violet-500/15 p-2 text-violet-300">
                  <Sparkles className="h-4 w-4" />
                </span>
                <div>
                  <div className="text-sm font-semibold text-white">ARIA Command</div>
                  <div className="font-mono text-[10px] uppercase tracking-[0.24em] text-slate-400">v4.0 Unified</div>
                </div>
              </div>
            </div>
            <button
              className="rounded-md border border-white/10 p-2 text-slate-400 transition hover:border-white/20 hover:text-white lg:hidden"
              onClick={onMobileClose}
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto px-3 py-4">
            <nav className="space-y-1.5">
              {navItems.map((item) => {
                const active = pathname === item.href;
                const Icon = item.icon;

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      "flex items-center gap-3 rounded-lg border border-transparent px-3 py-2.5 text-sm text-slate-300 transition hover:border-white/10 hover:bg-white/5 hover:text-white",
                      active && "border-blue-500/20 bg-blue-500/10 text-white",
                      collapsed && "justify-center px-0",
                    )}
                    onClick={onMobileClose}
                  >
                    <Icon className="h-4 w-4 shrink-0" />
                    {!collapsed ? <span>{item.label}</span> : null}
                  </Link>
                );
              })}
            </nav>

            <div className={cn("mt-5", collapsed && "hidden")}>
              <div className="rounded-lg border border-violet-500/20 bg-violet-500/10 p-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-medium text-white">ScamShield</div>
                    <div className="mt-1 text-xs text-slate-400">Rapid social-engineering screening</div>
                  </div>
                  <Badge tone="purple">New</Badge>
                </div>
              </div>
            </div>
          </div>

          <div className="border-t border-white/10 p-3">
            {!collapsed ? (
              <>
                <div className="mb-3 flex items-center gap-2">
                  <Waypoints className="h-4 w-4 text-blue-300" />
                  <span className="font-mono text-[11px] uppercase tracking-[0.24em] text-slate-400">
                    Asset Quick Stats
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {quickStats.map((item) => (
                    <div key={item.key} className="rounded-lg border border-white/10 bg-white/5 p-3">
                      <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-slate-500">
                        {item.label}
                      </div>
                      <div className="mt-2 text-xl font-semibold text-white">
                        {String(stats[item.key as keyof typeof stats] ?? 0)}
                      </div>
                    </div>
                  ))}
                </div>
              </>
            ) : null}

            <button
              className={cn(
                "mt-3 flex w-full items-center rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-300 transition hover:border-white/20 hover:text-white",
                collapsed ? "justify-center" : "justify-between",
              )}
              onClick={onCollapseToggle}
            >
              {!collapsed ? <span>Collapse Sidebar</span> : null}
              <ChevronLeft className={cn("h-4 w-4 transition", collapsed && "rotate-180")} />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}
