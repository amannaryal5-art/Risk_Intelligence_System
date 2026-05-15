"use client";

import { motion, useReducedMotion } from "framer-motion";

import { cn } from "@/lib/utils";

export function PulseDot({
  color = "success",
}: {
  color?: "success" | "warning" | "danger" | "accent";
}) {
  const reducedMotion = useReducedMotion();
  const colorMap = {
    success: { dot: "bg-success", ring: "border-success/60" },
    warning: { dot: "bg-warning", ring: "border-warning/60" },
    danger: { dot: "bg-danger", ring: "border-danger/60" },
    accent: { dot: "bg-accent", ring: "border-accent/60" },
  } as const;

  return (
    <span className="relative flex h-3 w-3 items-center justify-center">
      <span className={cn("h-2 w-2 rounded-full", colorMap[color].dot)} />
      {!reducedMotion ? (
        <motion.span
          className={cn("absolute inset-0 rounded-full border", colorMap[color].ring)}
          animate={{ scale: [1, 1.8], opacity: [1, 0] }}
          transition={{ duration: 2, repeat: Infinity }}
        />
      ) : null}
    </span>
  );
}
