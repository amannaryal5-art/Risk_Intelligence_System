"use client";

import { useState } from "react";

import { ReconnectModal } from "@/components/shared/ReconnectModal";
import { Sidebar } from "@/components/layout/Sidebar";
import { TopBar } from "@/components/layout/TopBar";

export function AppShell({ children }: { children: React.ReactNode }) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-transparent text-white">
      <Sidebar
        collapsed={sidebarCollapsed}
        mobileOpen={mobileSidebarOpen}
        onCollapseToggle={() => setSidebarCollapsed((current) => !current)}
        onMobileClose={() => setMobileSidebarOpen(false)}
      />

      <div
        className={`min-h-screen transition-[padding] duration-300 ${
          sidebarCollapsed ? "lg:pl-[60px]" : "lg:pl-[260px]"
        }`}
      >
        <TopBar onMobileMenuToggle={() => setMobileSidebarOpen((current) => !current)} />
        <main className="px-4 pb-6 pt-6 lg:px-6">{children}</main>
      </div>

      <ReconnectModal />
    </div>
  );
}
