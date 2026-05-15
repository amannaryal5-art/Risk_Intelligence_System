"use client";

import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import type { RiskCase } from "@/types/cases";

export function useCases(apiKey: string, limit = 5) {
  const [cases, setCases] = useState<RiskCase[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!apiKey) return;
    setIsLoading(true);
    setError(null);
    try {
      const response = await api.cases.list({ limit }, apiKey);
      setCases(response.results);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load cases");
    } finally {
      setIsLoading(false);
    }
  }, [apiKey, limit]);

  useEffect(() => {
    refresh().catch(() => null);
  }, [refresh]);

  return {
    cases,
    isLoading,
    error,
    refresh,
  };
}
