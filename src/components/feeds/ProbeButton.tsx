"use client";

import { RefreshCw, Radar, Zap } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";

import { Button } from "@/components/ui/button";

export function ProbeButton({
  isProbing,
  refreshSpin,
  onProbe,
  onRefresh,
}: {
  isProbing: boolean;
  refreshSpin: number;
  onProbe: () => void;
  onRefresh: () => void;
}) {
  const reducedMotion = useReducedMotion();

  return (
    <div className="flex items-center gap-3">
      <Button
        onClick={onProbe}
        className="relative overflow-hidden"
      >
        <Zap className="h-4 w-4" />
        <span>Probe All Feeds</span>
        {isProbing && !reducedMotion ? (
          <motion.span
            className="absolute inset-0 bg-[linear-gradient(120deg,transparent,rgba(255,255,255,0.42),transparent)]"
            initial={{ x: "-120%" }}
            animate={{ x: "120%" }}
            transition={{ duration: 0.8, repeat: Infinity, ease: "linear" }}
          />
        ) : null}
      </Button>
      <Button variant="outline" onClick={onRefresh}>
        <motion.span
          animate={reducedMotion ? { rotate: 0 } : { rotate: refreshSpin * 360 }}
          transition={{ duration: 0.8, ease: "easeInOut" }}
          className="inline-flex"
        >
          <RefreshCw className="h-4 w-4" />
        </motion.span>
        <span>Refresh Config</span>
      </Button>
      {isProbing ? <Radar className="h-4 w-4 animate-pulse text-accent" /> : null}
    </div>
  );
}
