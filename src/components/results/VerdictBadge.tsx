import { Badge } from "@/components/shared/Badge";

export function VerdictBadge({ verdict }: { verdict: "SAFE" | "CAUTION" | "DANGER" | "CRITICAL" }) {
  const tone =
    verdict === "CRITICAL" || verdict === "DANGER"
      ? "border-danger/30 bg-danger/10 text-danger"
      : verdict === "CAUTION"
        ? "border-warning/30 bg-warning/10 text-warning"
        : "border-success/30 bg-success/10 text-success";
  return <Badge className={tone}>{verdict}</Badge>;
}
