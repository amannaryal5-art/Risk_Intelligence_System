"use client";

import { startTransition, useState } from "react";

import { useAssets } from "@/hooks/useAssets";
import type { AssetType } from "@/lib/types";

const placeholders: Record<AssetType, string> = {
  domain: "e.g. example.com",
  ip: "e.g. 8.8.8.8",
  url: "e.g. https://example.com/login",
  email: "e.g. analyst@example.com",
};

export function AddAssetForm() {
  const { addAsset } = useAssets();
  const [label, setLabel] = useState("");
  const [type, setType] = useState<AssetType>("domain");
  const [value, setValue] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const submit = async () => {
    if (!value.trim()) return;
    setIsSubmitting(true);
    try {
      await addAsset({
        name: label.trim() || value.trim(),
        type,
        value: value.trim(),
      });
      startTransition(() => {
        setLabel("");
        setValue("");
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section className="panel p-4">
      <div className="eyebrow">Add Asset</div>
      <div className="mt-4 space-y-3">
        <input
          value={label}
          onChange={(event) => setLabel(event.target.value)}
          placeholder="e.g. My Site"
          className="w-full rounded-md border border-white/10 bg-black/20 px-3 py-2.5 text-sm text-white outline-none placeholder:text-slate-500 focus:border-blue-500/40"
        />
        <select
          value={type}
          onChange={(event) => setType(event.target.value as AssetType)}
          className="w-full rounded-md border border-white/10 bg-black/20 px-3 py-2.5 text-sm text-white outline-none focus:border-blue-500/40"
        >
          <option value="domain">Domain</option>
          <option value="ip">IP Address</option>
          <option value="url">URL</option>
          <option value="email">Email</option>
        </select>
        <input
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder={placeholders[type]}
          className="w-full rounded-md border border-white/10 bg-black/20 px-3 py-2.5 text-sm text-white outline-none placeholder:text-slate-500 focus:border-blue-500/40"
        />
        <button
          className="w-full rounded-md bg-blue-500 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-blue-400 disabled:cursor-not-allowed disabled:bg-blue-500/40"
          onClick={submit}
          disabled={isSubmitting || !value.trim()}
        >
          {isSubmitting ? "Adding..." : "Monitor this"}
        </button>
      </div>
    </section>
  );
}
