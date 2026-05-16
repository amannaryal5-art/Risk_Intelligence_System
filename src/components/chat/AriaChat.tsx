"use client";

import { SendHorizonal } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { ChatMessage } from "@/components/chat/ChatMessage";
import { QuickPrompts } from "@/components/chat/QuickPrompts";
import { useAssets } from "@/hooks/useAssets";

export function AriaChat() {
  const { chatHistory, sendChatMessage } = useAssets();
  const [input, setInput] = useState("");
  const [isSending, setIsSending] = useState(false);
  const viewportRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    viewportRef.current?.scrollTo({
      top: viewportRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [chatHistory]);

  const submit = async (message = input.trim()) => {
    if (!message) return;
    setIsSending(true);
    setInput("");
    try {
      await sendChatMessage(message);
    } finally {
      setIsSending(false);
    }
  };

  return (
    <section className="panel flex h-[calc(100vh-6.5rem)] flex-col overflow-hidden">
      <div className="border-b border-white/10 px-5 py-5">
        <div className="eyebrow">ARIA Analyst Interface</div>
        <h1 className="mt-2 text-2xl font-semibold text-white">Chat with the unified intelligence layer</h1>
        <p className="mt-3 max-w-3xl text-sm text-slate-300">
          ARIA can summarize threat posture, monitored asset exposure, and risk telemetry from VirusTotal,
          AbuseIPDB, and AlienVault OTX.
        </p>
        <div className="mt-4">
          <QuickPrompts onSelect={(prompt) => submit(prompt)} />
        </div>
      </div>

      <div ref={viewportRef} className="flex-1 space-y-4 overflow-y-auto px-5 py-5">
        {chatHistory.map((message) => (
          <ChatMessage key={message.id} message={message} />
        ))}
      </div>

      <div className="border-t border-white/10 p-4">
        <div className="flex items-end gap-3 rounded-2xl border border-white/10 bg-black/20 p-3">
          <textarea
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                submit();
              }
            }}
            placeholder="Ask ARIA about threats, assets, risk levels..."
            className="max-h-32 min-h-[52px] flex-1 resize-none bg-transparent px-1 py-2 text-sm text-white outline-none placeholder:text-slate-500"
          />
          <button
            className="inline-flex h-11 w-11 items-center justify-center rounded-xl bg-blue-500 text-white transition hover:bg-blue-400 disabled:cursor-not-allowed disabled:bg-blue-500/40"
            disabled={isSending || !input.trim()}
            onClick={() => submit()}
          >
            <SendHorizonal className="h-4 w-4" />
          </button>
        </div>
      </div>
    </section>
  );
}
