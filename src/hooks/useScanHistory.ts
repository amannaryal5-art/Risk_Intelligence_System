"use client";

import { useEffect, useState } from "react";

import type { InputType, UnifiedAnalysisResult } from "@/types/analysis";

export interface ScanHistoryItem {
  id: string;
  input: string;
  type: InputType;
  score: number;
  verdict: string;
  timestamp: string;
}

const STORAGE_KEY = "riskintel_scan_history";

export function useScanHistory() {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      setHistory(JSON.parse(raw) as ScanHistoryItem[]);
    } catch {}
  }, []);

  const persist = (items: ScanHistoryItem[]) => {
    setHistory(items);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
  };

  const addHistory = (result: UnifiedAnalysisResult) => {
    const item: ScanHistoryItem = {
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      input: result.input,
      type: result.type,
      score: result.score,
      verdict: result.verdict,
      timestamp: new Date().toISOString(),
    };
    const next = [item, ...history.filter((entry) => entry.input !== item.input)].slice(0, 10);
    persist(next);
  };

  return {
    history,
    addHistory,
  };
}
