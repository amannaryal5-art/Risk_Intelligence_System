"use client";

import { AssetsProvider } from "@/hooks/useAssets";
import { WebSocketProvider } from "@/hooks/useWebSocket";

export function AppProviders({ children }: { children: React.ReactNode }) {
  return (
    <WebSocketProvider>
      <AssetsProvider>{children}</AssetsProvider>
    </WebSocketProvider>
  );
}
