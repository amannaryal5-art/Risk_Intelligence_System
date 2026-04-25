"use client";

import { useState } from "react";

import { FeedProviderCard } from "@/components/feeds/FeedProviderCard";
import { FeedStatusFooter } from "@/components/feeds/FeedStatusFooter";
import { LiveFeedHeader } from "@/components/feeds/LiveFeedHeader";
import { SystemHealthBar } from "@/components/feeds/SystemHealthBar";
import { useLiveFeedPolling } from "@/hooks/useLiveFeedPolling";
import { feedProviders, systemHealth } from "@/lib/mockFeedData";

export default function LiveFeedsPage() {
  const { formattedTime, isProbing, runProbe } = useLiveFeedPolling();
  const [toast, setToast] = useState<string | null>(null);
  const [refreshSpin, setRefreshSpin] = useState(0);

  const handleRefresh = () => {
    setRefreshSpin((value) => value + 1);
    setToast("Config reloaded");
    window.setTimeout(() => setToast(null), 1800);
  };

  return (
    <main className="min-h-screen bg-bg px-4 py-6 text-white lg:px-8">
      <div className="mx-auto max-w-[1600px] space-y-6">
        <LiveFeedHeader
          formattedTime={formattedTime}
          isProbing={isProbing}
          refreshSpin={refreshSpin}
          onProbe={runProbe}
          onRefresh={handleRefresh}
        />

        <SystemHealthBar health={systemHealth} />

        <section className="grid grid-cols-1 gap-5 lg:grid-cols-3">
          {feedProviders.map((provider, index) => (
            <FeedProviderCard
              key={provider.id}
              provider={provider}
              index={index}
              isProbing={isProbing}
            />
          ))}
        </section>

        <FeedStatusFooter />
      </div>

      {toast ? (
        <div className="fixed bottom-6 right-6 rounded-lg border border-accent/25 bg-panel px-4 py-3 font-data text-xs uppercase tracking-[0.2em] text-accent shadow-cyan-glow">
          {toast}
        </div>
      ) : null}
    </main>
  );
}
