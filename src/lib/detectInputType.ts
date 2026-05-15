import type { InputType } from "@/types/analysis";

export function detectInputType(input: string): InputType {
  const trimmed = input.trim();
  if (!trimmed) return "text";
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return "ip";
  if (/^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/.test(trimmed) && trimmed.includes(":")) return "ip";
  if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return "hash_md5";
  if (/^[a-fA-F0-9]{40}$/.test(trimmed)) return "hash_sha1";
  if (/^[a-fA-F0-9]{64}$/.test(trimmed)) return "hash_sha256";
  if (/^https?:\/\//i.test(trimmed)) return "url";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return "email";
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(trimmed)) return "domain";
  const lines = trimmed.split("\n").filter((line) => line.trim());
  if (lines.length > 1) return "batch";
  return "text";
}

export function labelForInputType(type: InputType) {
  switch (type) {
    case "ip":
      return "IPv4 / IPv6";
    case "domain":
      return "Domain";
    case "url":
      return "URL";
    case "hash_md5":
      return "MD5";
    case "hash_sha1":
      return "SHA1";
    case "hash_sha256":
      return "SHA256";
    case "email":
      return "Email";
    case "batch":
      return "Batch";
    default:
      return "Text";
  }
}
