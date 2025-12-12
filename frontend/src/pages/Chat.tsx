import { FormEvent, useMemo, useState } from "react";

import { chatApi } from "../api/chat";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
  meta?: { used_llm?: boolean; model?: string | null };
};

function classFor(role: ChatMessage["role"]) {
  if (role === "user") {
    return "ml-auto bg-blue-600 text-white";
  }
  return "mr-auto bg-gray-100 text-gray-900";
}

export default function Chat() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSend = useMemo(
    () => input.trim().length > 0 && !isSending,
    [input, isSending]
  );

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const text = input.trim();
    if (!text) return;

    setError(null);
    setInput("");
    setIsSending(true);
    setMessages((prev) => [...prev, { role: "user", content: text }]);

    try {
      const resp = await chatApi.send({ message: text });
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: resp.response,
          meta: { used_llm: resp.used_llm, model: resp.model },
        },
      ]);
    } catch (err: any) {
      setError(err?.message || "Failed to send message.");
    } finally {
      setIsSending(false);
    }
  }

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-4">
      <div>
        <h1 className="text-2xl font-semibold">Chat</h1>
        <p className="mt-1 text-sm text-gray-600">
          Ask DataBug AI about incidents, bugs, and root causes.
        </p>
      </div>

      <div className="rounded-lg border bg-white p-4">
        <div className="space-y-3">
          {messages.length === 0 && (
            <div className="text-sm text-gray-500">
              Try: “Explain the likely root cause of the latest incident.”
            </div>
          )}
          {messages.map((m, idx) => (
            <div key={idx} className={`max-w-[85%] rounded-lg px-3 py-2 ${classFor(m.role)}`}>
              <div className="whitespace-pre-wrap text-sm">{m.content}</div>
              {m.role === "assistant" && m.meta?.used_llm === false && (
                <div className="mt-1 text-xs opacity-80">
                  Fallback response (LLM unavailable)
                </div>
              )}
              {m.role === "assistant" && m.meta?.used_llm && m.meta?.model && (
                <div className="mt-1 text-xs opacity-80">Model: {m.meta.model}</div>
              )}
            </div>
          ))}
        </div>
      </div>

      {error && <div className="text-sm text-red-600">{error}</div>}

      <form onSubmit={onSubmit} className="rounded-lg border bg-white p-4">
        <div className="flex flex-col gap-3">
          <textarea
            className="min-h-[84px] w-full resize-y rounded-md border px-3 py-2 text-sm"
            placeholder="Type your question..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={isSending}
          />
          <div className="flex items-center justify-between">
            <div className="text-xs text-gray-500">
              Endpoint: <span className="font-mono">/api/chat</span>
            </div>
            <button
              type="submit"
              disabled={!canSend}
              className="rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              {isSending ? "Sending..." : "Send"}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}

