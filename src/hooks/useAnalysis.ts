"use client";

import { useState } from "react";

import { runAnalysis } from "@/lib/analyze";
import type { TerminalEntry, UnifiedAnalysisResult } from "@/types/analysis";

export function useAnalysis() {
  const [result, setResult] = useState<UnifiedAnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [terminalEntries, setTerminalEntries] = useState<TerminalEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  const pushLog = (entry: TerminalEntry) => {
    setTerminalEntries((current) => [...current.slice(-119), entry]);
  };

  const analyze = async (params: {
    input: string;
    apiKey: string;
    autopilot: boolean;
    file?: File | null;
  }) => {
    setIsAnalyzing(true);
    setError(null);
    setTerminalEntries([]);
    try {
      const next = await runAnalysis(
        params.input,
        params.apiKey,
        params.autopilot,
        params.file,
        pushLog,
      );
      setResult(next);
      return next;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Analysis failed";
      setError(message);
      pushLog({
        id: `${Date.now()}-error`,
        tone: "danger",
        message: `<- ERROR ${message}`,
        timestamp: new Date().toISOString(),
      });
      throw err;
    } finally {
      setIsAnalyzing(false);
    }
  };

  return {
    result,
    setResult,
    isAnalyzing,
    terminalEntries,
    error,
    analyze,
  };
}
