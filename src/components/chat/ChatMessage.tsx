import type { ChatMessage as ChatMessageType } from "@/lib/types";

export function ChatMessage({ message }: { message: ChatMessageType }) {
  const isAssistant = message.role === "assistant";

  return (
    <div className={`flex gap-3 ${isAssistant ? "justify-start" : "justify-end"}`}>
      {isAssistant ? (
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-violet-500/15 text-sm font-semibold text-violet-300">
          A
        </div>
      ) : null}

      <div
        className={`max-w-[78%] rounded-2xl px-4 py-3 text-sm leading-6 ${
          isAssistant
            ? "border border-violet-500/20 bg-violet-500/10 text-slate-100"
            : "bg-blue-500 text-white"
        }`}
      >
        <p className="whitespace-pre-wrap">{message.content}</p>
      </div>

      {!isAssistant ? (
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-blue-500/15 text-sm font-semibold text-blue-200">
          U
        </div>
      ) : null}
    </div>
  );
}
