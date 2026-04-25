import type { FeedProvider, SystemHealth } from "@/types/feeds";

export const systemHealth: SystemHealth = {
  cfg: { current: 3, total: 5 },
  net: { current: 3, total: 5 },
  auth: { current: 3, total: 5 },
};

export const feedProviders: FeedProvider[] = [
  {
    id: "alienvault-otx",
    name: "AlienVaultOTX",
    description:
      "Open threat intelligence community. Detects malicious IPs, domains, hashes via 20M+ IOCs.",
    status: "READY",
    httpCode: 200,
    latencyMs: 1398,
    quotaPercent: 80,
    tier: "Free tier",
    capabilities: ["IP reputation", "Domain lookup", "Hash analysis", "Bulk queries"],
    icon: "◉",
    latestScan: {
      url: "cognexiaailegal.com/legal/te...",
      fields: [{ label: "OTX pulses", value: 0 }],
      threatScore: "0/100",
      verdict: "CLEAN",
    },
  },
  {
    id: "abuse-ipdb",
    name: "AbuseIPDB",
    description:
      "IP address abuse reporting. Checks IPs against reported malicious activity.",
    status: "READY",
    httpCode: 200,
    latencyMs: 984,
    quotaPercent: 80,
    tier: "Free tier",
    capabilities: ["IP reputation", "Reporter trends", "Confidence scoring", "Enrichment"],
    icon: "◆",
    latestScan: {
      url: "cognexiaailegal.com/legal/te...",
      fields: [{ label: "Abuse confidence", value: 0 }],
      threatScore: "0/100",
      verdict: "CLEAN",
    },
  },
  {
    id: "virus-total",
    name: "VirusTotal",
    description: "Multi-engine malware scanner. Aggregates 70+ antivirus engines.",
    status: "READY",
    httpCode: 200,
    latencyMs: 375,
    quotaPercent: 80,
    tier: "Free tier",
    capabilities: ["Hash analysis", "URL scan", "Domain intel", "Multi-engine verdict"],
    icon: "▣",
    latestScan: {
      url: "cognexiaailegal.com/legal/te...",
      fields: [{ label: "VT malicious", value: 0 }],
      threatScore: "0/100",
      verdict: "CLEAN",
    },
  },
];
