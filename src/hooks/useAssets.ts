"use client";

import {
  createContext,
  useContext,
  useEffect,
  useEffectEvent,
  useMemo,
  useState,
} from "react";

import { api } from "@/lib/api";
import type {
  Asset,
  AssetAlert,
  AssetHistoryEntry,
  AssetStats,
  AssetSummaryResponse,
  AssetType,
  ChatMessage,
} from "@/lib/types";

interface AddAssetPayload {
  name: string;
  type: AssetType;
  value: string;
}

interface AssetsContextValue {
  assets: Asset[];
  stats: AssetStats;
  alerts: AssetAlert[];
  chatHistory: ChatMessage[];
  autoMonitoring: boolean;
  isLoadingAssets: boolean;
  selectedAssetId: number | null;
  selectedAsset: Asset | null;
  addAsset: (payload: AddAssetPayload) => Promise<void>;
  deleteAsset: (id: number) => Promise<void>;
  scanAsset: (id: number) => Promise<void>;
  selectAsset: (id: number | null) => void;
  refreshAssets: () => Promise<void>;
  markAlertSeen: (id: number) => Promise<void>;
  markAllAlertsSeen: () => Promise<void>;
  fetchAssetHistory: (id: number) => Promise<AssetHistoryEntry[]>;
  fetchAssetSummary: (id: number) => Promise<AssetSummaryResponse>;
  sendChatMessage: (message: string) => Promise<void>;
}

const initialStats: AssetStats = {
  total: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  clean: 0,
  unknown: 0,
  unseen_alerts: 0,
};

const initialChat: ChatMessage[] = [
  {
    id: "intro",
    role: "assistant",
    content: "Hello. I'm ARIA - your AI risk intelligence analyst.",
    createdAt: new Date().toISOString(),
  },
  {
    id: "intro-context",
    role: "assistant",
    content:
      "I'm monitoring all your registered assets around the clock and analyzing threats in real time using VirusTotal, AbuseIPDB, and AlienVault OTX.",
    createdAt: new Date().toISOString(),
  },
];

const AssetsContext = createContext<AssetsContextValue | null>(null);

export function AssetsProvider({ children }: { children: React.ReactNode }) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [stats, setStats] = useState<AssetStats>(initialStats);
  const [alerts, setAlerts] = useState<AssetAlert[]>([]);
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>(initialChat);
  const [selectedAssetId, setSelectedAssetId] = useState<number | null>(null);
  const [isLoadingAssets, setIsLoadingAssets] = useState(true);

  const refreshAssets = useEffectEvent(async () => {
    setIsLoadingAssets(true);
    try {
      const [nextAssets, nextStats, nextAlerts] = await Promise.all([
        api.aria.assets(),
        api.aria.stats(),
        api.aria.alerts(),
      ]);
      setAssets(nextAssets);
      setStats(nextStats);
      setAlerts(nextAlerts);
      setSelectedAssetId((current) => {
        if (current && nextAssets.some((asset) => asset.id === current)) return current;
        return nextAssets[0]?.id ?? null;
      });
    } finally {
      setIsLoadingAssets(false);
    }
  });

  useEffect(() => {
    refreshAssets().catch(() => {
      setIsLoadingAssets(false);
    });

    const interval = window.setInterval(() => {
      refreshAssets().catch(() => null);
    }, 60000);

    return () => window.clearInterval(interval);
  }, [refreshAssets]);

  const addAsset = useEffectEvent(async (payload: AddAssetPayload) => {
    await api.aria.addAsset(payload);
    await refreshAssets();
  });

  const deleteAsset = useEffectEvent(async (id: number) => {
    await api.aria.deleteAsset(id);
    await refreshAssets();
  });

  const scanAsset = useEffectEvent(async (id: number) => {
    await api.aria.scanAsset(id);
    window.setTimeout(() => {
      refreshAssets().catch(() => null);
    }, 8000);
    window.setTimeout(() => {
      refreshAssets().catch(() => null);
    }, 20000);
  });

  const markAlertSeen = useEffectEvent(async (id: number) => {
    await api.aria.markAlertSeen(id);
    await refreshAssets();
  });

  const markAllAlertsSeen = useEffectEvent(async () => {
    await api.aria.markAllAlertsSeen();
    await refreshAssets();
  });

  const sendChatMessage = useEffectEvent(async (message: string) => {
    const nextUserMessage: ChatMessage = {
      id: `user-${crypto.randomUUID()}`,
      role: "user",
      content: message,
      createdAt: new Date().toISOString(),
    };

    const pendingHistory = [...chatHistory, nextUserMessage];
    setChatHistory(pendingHistory);

    try {
      const reply = await api.aria.chat(
        pendingHistory.map((entry) => ({
          role: entry.role,
          content: entry.content,
        })),
      );

      setChatHistory((current) => [
        ...current,
        {
          id: `assistant-${crypto.randomUUID()}`,
          role: "assistant",
          content: reply.reply || "No response received.",
          createdAt: new Date().toISOString(),
        },
      ]);
    } catch {
      setChatHistory((current) => [
        ...current,
        {
          id: `assistant-${crypto.randomUUID()}`,
          role: "assistant",
          content: "Connection error. Check that the backend is running and reachable.",
          createdAt: new Date().toISOString(),
        },
      ]);
    }
  });

  const value = useMemo<AssetsContextValue>(
    () => ({
      assets,
      stats,
      alerts,
      chatHistory,
      autoMonitoring: true,
      isLoadingAssets,
      selectedAssetId,
      selectedAsset: assets.find((asset) => asset.id === selectedAssetId) ?? null,
      addAsset,
      deleteAsset,
      scanAsset,
      selectAsset: setSelectedAssetId,
      refreshAssets,
      markAlertSeen,
      markAllAlertsSeen,
      fetchAssetHistory: api.aria.assetHistory,
      fetchAssetSummary: api.aria.assetSummary,
      sendChatMessage,
    }),
    [
      addAsset,
      alerts,
      assets,
      chatHistory,
      isLoadingAssets,
      markAlertSeen,
      markAllAlertsSeen,
      refreshAssets,
      scanAsset,
      selectedAssetId,
      sendChatMessage,
      stats,
    ],
  );

  return <AssetsContext.Provider value={value}>{children}</AssetsContext.Provider>;
}

export function useAssets() {
  const context = useContext(AssetsContext);
  if (!context) {
    throw new Error("useAssets must be used within AssetsProvider");
  }
  return context;
}
