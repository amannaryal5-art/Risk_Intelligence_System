"use client";

import { useEffect, useState } from "react";

const easeOut = (value: number) => 1 - Math.pow(1 - value, 3);

export function CountUp({
  from = 0,
  to,
  duration = 1,
}: {
  from?: number;
  to: number;
  duration?: number;
}) {
  const [value, setValue] = useState(from);

  useEffect(() => {
    const start = performance.now();
    let frame = 0;

    const tick = (now: number) => {
      const elapsed = Math.min(1, (now - start) / (duration * 1000));
      setValue(Math.round(from + (to - from) * easeOut(elapsed)));
      if (elapsed < 1) frame = window.requestAnimationFrame(tick);
    };

    frame = window.requestAnimationFrame(tick);
    return () => window.cancelAnimationFrame(frame);
  }, [duration, from, to]);

  return <span>{value}</span>;
}
