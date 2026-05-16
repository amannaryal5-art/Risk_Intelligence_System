"use client";

import {
  createContext,
  useContext,
  useEffect,
  useEffectEvent,
  useMemo,
  useRef,
  useState,
} from "react";

import { API_BASE } from "@/lib/api";
import type { WebSocketStatus } from "@/lib/types";

interface WebSocketContextValue {
  status: WebSocketStatus;
  reconnectIn: number;
  queuedActions: number;
  send: (payload: unknown) => void;
  connect: () => void;
  disconnect: () => void;
}

const WebSocketContext = createContext<WebSocketContextValue | null>(null);

function resolveEndpoint() {
  if (typeof window === "undefined") return null;
  const explicit = process.env.NEXT_PUBLIC_WS_URL?.trim();
  if (explicit) return explicit;
  const normalizedBase = API_BASE.replace(/^http/, "ws").replace(/\/$/, "");
  return `${normalizedBase}/ws/control-plane`;
}

export function WebSocketProvider({ children }: { children: React.ReactNode }) {
  const socketRef = useRef<WebSocket | null>(null);
  const manualCloseRef = useRef(false);
  const retryTimeoutRef = useRef<number | null>(null);
  const countdownRef = useRef<number | null>(null);
  const retryAttemptRef = useRef(0);
  const queueRef = useRef<string[]>([]);
  const endpointRef = useRef<string | null>(null);

  const [status, setStatus] = useState<WebSocketStatus>("disconnected");
  const [reconnectIn, setReconnectIn] = useState(0);
  const [queuedActions, setQueuedActions] = useState(0);

  const clearTimers = useEffectEvent(() => {
    if (retryTimeoutRef.current) {
      window.clearTimeout(retryTimeoutRef.current);
      retryTimeoutRef.current = null;
    }
    if (countdownRef.current) {
      window.clearInterval(countdownRef.current);
      countdownRef.current = null;
    }
  });

  const flushQueue = useEffectEvent(() => {
    const socket = socketRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) return;

    for (const item of queueRef.current) {
      socket.send(item);
    }

    queueRef.current = [];
    setQueuedActions(0);
  });

  const scheduleReconnect = useEffectEvent(() => {
    clearTimers();
    retryAttemptRef.current += 1;
    const delay = Math.min(30, Math.max(2, 2 ** retryAttemptRef.current));
    setStatus("reconnecting");
    setReconnectIn(delay);

    countdownRef.current = window.setInterval(() => {
      setReconnectIn((current) => (current > 0 ? current - 1 : 0));
    }, 1000);

    retryTimeoutRef.current = window.setTimeout(() => {
      clearTimers();
      connect();
    }, delay * 1000);
  });

  const connect = useEffectEvent(() => {
    const endpoint = endpointRef.current;
    if (!endpoint || typeof window === "undefined") {
      setStatus("disconnected");
      return;
    }

    const current = socketRef.current;
    if (current && (current.readyState === WebSocket.OPEN || current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    manualCloseRef.current = false;

    try {
      const socket = new WebSocket(endpoint);
      socketRef.current = socket;

      socket.onopen = () => {
        retryAttemptRef.current = 0;
        clearTimers();
        setReconnectIn(0);
        setStatus("connected");
        flushQueue();
      };

      socket.onclose = () => {
        socketRef.current = null;
        if (manualCloseRef.current) {
          clearTimers();
          setReconnectIn(0);
          setStatus("disconnected");
          return;
        }
        scheduleReconnect();
      };

      socket.onerror = () => {
        socket.close();
      };
    } catch {
      scheduleReconnect();
    }
  });

  const disconnect = useEffectEvent(() => {
    manualCloseRef.current = true;
    clearTimers();
    socketRef.current?.close();
    socketRef.current = null;
    setReconnectIn(0);
    setStatus("disconnected");
  });

  const send = useEffectEvent((payload: unknown) => {
    const serialized = typeof payload === "string" ? payload : JSON.stringify(payload);
    const socket = socketRef.current;

    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(serialized);
      return;
    }

    queueRef.current.push(serialized);
    setQueuedActions(queueRef.current.length);

    if (status === "disconnected") {
      connect();
    }
  });

  useEffect(() => {
    endpointRef.current = resolveEndpoint();
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  const value = useMemo(
    () => ({
      status,
      reconnectIn,
      queuedActions,
      send,
      connect,
      disconnect,
    }),
    [connect, disconnect, queuedActions, reconnectIn, send, status],
  );

  return <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>;
}

export function useWebSocket() {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error("useWebSocket must be used within WebSocketProvider");
  }
  return context;
}
