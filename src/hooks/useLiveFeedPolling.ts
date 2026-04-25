"use client";

import { useEffect, useMemo, useState } from "react";

export function useLiveFeedPolling() {
  const [lastChecked, setLastChecked] = useState<Date>(new Date());
  const [probeTick, setProbeTick] = useState(0);
  const [isProbing, setIsProbing] = useState(false);

  useEffect(() => {
    const timer = window.setInterval(() => setLastChecked(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const formattedTime = useMemo(
    () =>
      lastChecked.toLocaleTimeString([], {
        hour: "numeric",
        minute: "2-digit",
        second: "2-digit",
      }),
    [lastChecked],
  );

  const runProbe = async () => {
    setIsProbing(true);
    await new Promise((resolve) => window.setTimeout(resolve, 2000));
    setProbeTick((value) => value + 1);
    setIsProbing(false);
  };

  return {
    formattedTime,
    isProbing,
    probeTick,
    runProbe,
  };
}
