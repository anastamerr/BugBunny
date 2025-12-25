import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { chatApi } from "../api/chat";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
  meta?: { used_llm?: boolean; model?: string | null };
};

function messageClass(role: ChatMessage["role"]) {
  if (role === "user") {
    return "ml-auto bg-neon-mint text-void";
  }
  return "mr-auto border border-white/10 bg-surface text-white";
}

export default function Chat() {
  const [searchParams] = useSearchParams();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const bugId = searchParams.get("bug_id") || undefined;
  const scanId = searchParams.get("scan_id") || undefined;
  const findingId = searchParams.get("finding_id") || undefined;
  const prefill = searchParams.get("message") || searchParams.get("q") || "";

  useEffect(() => {
    if (prefill && messages.length === 0 && !input) {
      setInput(prefill);
    }
  }, [prefill, messages.length, input]);

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
      const resp = await chatApi.send({
        message: text,
        bug_id: bugId,
        scan_id: scanId,
        finding_id: findingId,
      });
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: resp.response,
          meta: { used_llm: resp.used_llm, model: resp.model },
        },
      ]);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to send message.");
    } finally {
      setIsSending(false);
    }
  }

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-6">
      <div className="surface-solid p-6">
        <h1 className="text-2xl font-extrabold tracking-tight text-white">Chat</h1>
        <p className="mt-1 text-sm text-white/60">
          Ask ScanGuard AI about scans, findings, and triage recommendations. The
          assistant is grounded in your latest platform data.
        </p>
        {(bugId || scanId || findingId) ? (
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-white/60">
            {scanId ? (
              <Link to={`/scans/${scanId}`} className="badge font-mono text-white/80">
                scan {scanId.slice(0, 8)}
              </Link>
            ) : null}
            {findingId ? (
              <span className="badge font-mono text-white/80">
                finding {findingId.slice(0, 8)}
              </span>
            ) : null}
            {bugId ? (
              <Link to={`/bugs/${bugId}`} className="badge font-mono text-white/80">
                bug {bugId.slice(0, 8)}
              </Link>
            ) : null}
            <Link to="/chat" className="btn-ghost">
              Clear context
            </Link>
          </div>
        ) : null}
      </div>

      <div className="surface-solid p-5">
        <div className="space-y-3">
          {messages.length === 0 && (
            <div className="text-sm text-white/60">
              Try: "Summarize the latest high-severity findings."
            </div>
          )}

          {messages.map((message, idx) => (
            <div
              key={idx}
              className={`max-w-[90%] rounded-card px-4 py-3 text-sm shadow-[0_12px_40px_rgba(0,0,0,0.35)] ${messageClass(
                message.role
              )}`}
            >
              <div className="whitespace-pre-wrap">{message.content}</div>

              {message.role === "assistant" && message.meta?.used_llm === false && (
                <div className="mt-2 text-xs text-white/60">
                  Fallback response (LLM unavailable)
                </div>
              )}
              {message.role === "assistant" &&
                message.meta?.used_llm &&
                message.meta?.model && (
                  <div className="mt-2 text-xs text-white/60">
                    Model: {message.meta.model}
                  </div>
                )}
            </div>
          ))}
        </div>
      </div>

      {error && (
        <div className="rounded-card border border-white/10 bg-void p-4 text-sm text-white/80">
          {error}
        </div>
      )}

      <form onSubmit={onSubmit} className="surface-solid p-5">
        <div className="flex flex-col gap-3">
          <textarea
            className="min-h-[92px] w-full resize-y rounded-card border-2 border-white/10 bg-void px-4 py-3 text-sm text-white placeholder-white/30 outline-none transition-colors duration-200 ease-fluid focus:border-neon-mint disabled:opacity-60"
            placeholder="Type your question..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={isSending}
          />
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-xs text-white/60">
              Endpoint: <span className="font-mono text-white/80">/api/chat</span>{" "}
              <span className="badge ml-2 border-neon-mint/40 bg-neon-mint/10 text-neon-mint">
                Auto-context
              </span>
            </div>
            <button type="submit" disabled={!canSend} className="btn-primary">
              {isSending ? "Sending..." : "Send"}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
