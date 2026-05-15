"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import { API_BASE, api } from "@/lib/api";
import type { FeedStatusResponse } from "@/types/feeds";

function formatTime(value?: string) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleTimeString([], {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function useLiveFeedPolling(apiKey?: string) {
  const [feedData, setFeedData] = useState<FeedStatusResponse | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isProbing, setIsProbing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const pollViaHttp = async () => {
    const data = await api.feedsStatus(apiKey);
    setFeedData(data);
    setLastUpdated(data.timestamp);
  };

  const runProbe = async () => {
    setIsProbing(true);
    try {
      const data = await api.feedsProbe(apiKey);
      setFeedData(data);
      setLastUpdated(data.timestamp);
    } finally {
      setIsProbing(false);
    }
  };

  useEffect(() => {
    let active = true;
    let pollTimer: number | undefined;
    const wsUrl = `${API_BASE.replace(/^http/, "ws")}/api/v1/ws/feeds/status`;

    const connect = () => {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      ws.onopen = () => {
        if (!active) return;
        setIsConnected(true);
      };
      ws.onmessage = (event) => {
        if (!active) return;
        try {
          const payload = JSON.parse(event.data) as {
            timestamp?: string;
            data?: FeedStatusResponse;
          };
          if (payload.data) {
            setFeedData(payload.data);
            setLastUpdated(payload.timestamp ?? payload.data.timestamp);
          }
        } catch {}
      };
      ws.onerror = async () => {
        if (!active) return;
        setIsConnected(false);
        await pollViaHttp().catch(() => null);
      };
      ws.onclose = () => {
        if (!active) return;
        setIsConnected(false);
      };
    };

    pollViaHttp().catch(() => null);
    connect();
    pollTimer = window.setInterval(() => {
      pollViaHttp().catch(() => null);
    }, 30000);

    return () => {
      active = false;
      if (pollTimer) window.clearInterval(pollTimer);
      wsRef.current?.close();
    };
  }, [apiKey]);

  const formattedTime = useMemo(() => formatTime(lastUpdated ?? undefined), [lastUpdated]);

  return {
    feedData,
    isConnected,
    isProbing,
    runProbe,
    formattedTime,
    lastUpdated,
  };
}
