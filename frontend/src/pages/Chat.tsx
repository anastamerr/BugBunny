import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { Square } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { bugsApi } from "../api/bugs";
import { chatApi } from "../api/chat";
import { scansApi } from "../api/scans";
import type { BugReport, Finding } from "../types";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
  meta?: { used_llm?: boolean; model?: string | null };
};

type MentionItem = {
  type: "finding" | "bug";
  id: string;
  label: string;
  subtitle: string;
};

type FocusContext = {
  type: "finding" | "bug" | "scan";
  id: string;
  label: string;
};

function messageClass(role: ChatMessage["role"]) {
  if (role === "user") {
    return "ml-auto bg-neon-mint text-void";
  }
  return "mr-auto border border-white/10 bg-surface text-white";
}

function truncateLabel(value: string, max = 48) {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 3)}...`;
}

const markdownComponents = {
  p: ({ children }: { children?: ReactNode }) => (
    <p className="text-sm leading-relaxed">{children}</p>
  ),
  ul: ({ children }: { children?: ReactNode }) => (
    <ul className="list-disc space-y-1 pl-5 text-sm leading-relaxed">
      {children}
    </ul>
  ),
  ol: ({ children }: { children?: ReactNode }) => (
    <ol className="list-decimal space-y-1 pl-5 text-sm leading-relaxed">
      {children}
    </ol>
  ),
  li: ({ children }: { children?: ReactNode }) => (
    <li className="text-sm leading-relaxed">{children}</li>
  ),
  a: ({
    children,
    href,
  }: {
    children?: ReactNode;
    href?: string;
  }) => (
    <a
      href={href}
      className="underline decoration-white/30 underline-offset-4 hover:decoration-neon-mint/60"
      target="_blank"
      rel="noreferrer"
    >
      {children}
    </a>
  ),
  code: ({
    children,
    className,
    inline,
  }: {
    children?: ReactNode;
    className?: string;
    inline?: boolean;
  }) =>
    inline ? (
      <code className="rounded bg-white/10 px-1 font-mono text-xs text-white/90">
        {children}
      </code>
    ) : (
      <code className={className}>{children}</code>
    ),
  pre: ({ children }: { children?: ReactNode }) => (
    <pre className="mt-2 overflow-auto rounded-card border border-white/10 bg-void p-3 text-xs text-white/80">
      {children}
    </pre>
  ),
  strong: ({ children }: { children?: ReactNode }) => (
    <strong className="font-semibold text-white">{children}</strong>
  ),
};

function buildFindingMention(finding: Finding): MentionItem {
  const severity = finding.ai_severity || finding.semgrep_severity;
  return {
    type: "finding",
    id: finding.id,
    label: `${finding.rule_id} ${finding.file_path}:${finding.line_start}`,
    subtitle: `finding ${severity}`,
  };
}

function buildBugMention(bug: BugReport): MentionItem {
  return {
    type: "bug",
    id: bug.id,
    label: bug.title,
    subtitle: `bug ${bug.classified_severity}`,
  };
}

export default function Chat() {
  const [searchParams] = useSearchParams();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mentionOpen, setMentionOpen] = useState(false);
  const [mentionQuery, setMentionQuery] = useState("");
  const [mentionIndex, setMentionIndex] = useState(0);
  const [mentionStart, setMentionStart] = useState<number | null>(null);
  const [manualContext, setManualContext] = useState(false);
  const [activeContext, setActiveContext] = useState<FocusContext | null>(null);

  const inputRef = useRef<HTMLTextAreaElement | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const assistantIndexRef = useRef<number | null>(null);

  const bugId = searchParams.get("bug_id") || undefined;
  const scanId = searchParams.get("scan_id") || undefined;
  const findingId = searchParams.get("finding_id") || undefined;
  const prefill = searchParams.get("message") || searchParams.get("q") || "";

  const baseContext = useMemo<FocusContext | null>(() => {
    if (findingId) {
      return {
        type: "finding",
        id: findingId,
        label: `finding ${findingId.slice(0, 8)}`,
      };
    }
    if (bugId) {
      return { type: "bug", id: bugId, label: `bug ${bugId.slice(0, 8)}` };
    }
    if (scanId) {
      return { type: "scan", id: scanId, label: `scan ${scanId.slice(0, 8)}` };
    }
    return null;
  }, [bugId, scanId, findingId]);

  useEffect(() => {
    if (!manualContext) {
      setActiveContext(baseContext);
    }
  }, [baseContext, manualContext]);

  useEffect(() => {
    if (prefill && messages.length === 0 && !input) {
      setInput(prefill);
    }
  }, [prefill, messages.length, input]);

  const { data: mentionFindings = [] } = useQuery({
    queryKey: ["mentions", "findings"],
    queryFn: () =>
      scansApi.listFindings({ limit: 20, include_false_positives: false }),
  });

  const { data: mentionBugs = [] } = useQuery({
    queryKey: ["mentions", "bugs"],
    queryFn: () => bugsApi.getAll({ limit: 20 }),
  });

  const mentionItems = useMemo<MentionItem[]>(() => {
    const findings = (mentionFindings || []).map(buildFindingMention);
    const bugs = (mentionBugs || []).map(buildBugMention);
    return [...findings, ...bugs];
  }, [mentionFindings, mentionBugs]);

  const mentionSuggestions = useMemo(() => {
    const query = mentionQuery.trim().toLowerCase();
    const filtered = query
      ? mentionItems.filter((item) => {
          const label = item.label.toLowerCase();
          const subtitle = item.subtitle.toLowerCase();
          return label.includes(query) || subtitle.includes(query);
        })
      : mentionItems;
    return filtered.slice(0, 8);
  }, [mentionItems, mentionQuery]);

  useEffect(() => {
    if (mentionOpen) {
      setMentionIndex(0);
    }
  }, [mentionOpen, mentionQuery]);

  const canSend = useMemo(
    () => input.trim().length > 0 && !isSending,
    [input, isSending]
  );

  function closeMention() {
    setMentionOpen(false);
    setMentionQuery("");
    setMentionStart(null);
    setMentionIndex(0);
  }

  function updateMentionState(value: string, cursor: number) {
    const before = value.slice(0, cursor);
    const atIndex = before.lastIndexOf("@");
    if (atIndex < 0) {
      closeMention();
      return;
    }

    const prevChar = atIndex === 0 ? " " : before[atIndex - 1];
    if (prevChar !== " " && prevChar !== "\n") {
      closeMention();
      return;
    }

    const query = before.slice(atIndex + 1);
    if (query.includes(" ") || query.includes("\n")) {
      closeMention();
      return;
    }

    setMentionOpen(true);
    setMentionQuery(query);
    setMentionStart(atIndex);
  }

  function handleSelectMention(item: MentionItem) {
    const textarea = inputRef.current;
    const current = input;
    const cursor = textarea?.selectionStart ?? current.length;
    const start = mentionStart ?? current.lastIndexOf("@");
    if (start < 0) return;

    const before = current.slice(0, start);
    const after = current.slice(cursor);
    const mentionText = `@${item.label}`;
    const nextValue = `${before}${mentionText} ${after}`;

    setInput(nextValue);
    setManualContext(true);
    setActiveContext({
      type: item.type,
      id: item.id,
      label: `${item.type} ${truncateLabel(item.label, 36)}`,
    });
    closeMention();

    requestAnimationFrame(() => {
      if (textarea) {
        const pos = (before + mentionText + " ").length;
        textarea.focus();
        textarea.setSelectionRange(pos, pos);
      }
    });
  }

  function handleKeyDown(event: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (!mentionOpen) return;

    if (event.key === "ArrowDown") {
      if (mentionSuggestions.length === 0) return;
      event.preventDefault();
      setMentionIndex((prev) =>
        Math.min(prev + 1, mentionSuggestions.length - 1)
      );
      return;
    }
    if (event.key === "ArrowUp") {
      if (mentionSuggestions.length === 0) return;
      event.preventDefault();
      setMentionIndex((prev) => Math.max(prev - 1, 0));
      return;
    }
    if (event.key === "Enter" && mentionSuggestions.length > 0) {
      event.preventDefault();
      handleSelectMention(mentionSuggestions[mentionIndex]);
      return;
    }
    if (event.key === "Escape") {
      closeMention();
    }
  }

  function buildPayload(message: string) {
    const context = activeContext;
    return {
      message,
      bug_id: context?.type === "bug" ? context.id : undefined,
      scan_id: context?.type === "scan" ? context.id : undefined,
      finding_id: context?.type === "finding" ? context.id : undefined,
    };
  }

  function updateAssistantMeta(used: boolean, model: string | null) {
    setMessages((prev) => {
      const index = assistantIndexRef.current;
      if (index === null || !prev[index]) return prev;
      const next = [...prev];
      next[index] = {
        ...next[index],
        meta: { used_llm: used, model },
      };
      return next;
    });
  }

  function appendAssistantChunk(chunk: string) {
    setMessages((prev) => {
      const index = assistantIndexRef.current;
      if (index === null || !prev[index]) return prev;
      const next = [...prev];
      const current = next[index];
      next[index] = {
        ...current,
        content: `${current.content}${chunk}`,
      };
      return next;
    });
  }

  async function readStream(response: Response) {
    if (!response.body) {
      throw new Error("Streaming response is not available.");
    }

    const usedHeader = response.headers.get("X-LLM-Used");
    const used = usedHeader ? usedHeader !== "false" : true;
    const model = response.headers.get("X-LLM-Model");
    updateAssistantMeta(used, model);

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() || "";

      for (const part of parts) {
        const lines = part.split("\n");
        const dataLines: string[] = [];
        for (const line of lines) {
          const cleaned = line.replace(/\r$/, "");
          if (!cleaned.startsWith("data:")) {
            continue;
          }
          let content = cleaned.slice(5);
          if (content.startsWith(" ")) {
            content = content.slice(1);
          }
          dataLines.push(content);
        }

        if (dataLines.length === 0) continue;
        const data = dataLines.join("\n");
        if (data === "[DONE]") {
          return;
        }
        appendAssistantChunk(data);
      }
    }
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (isSending) return;
    const text = input.trim();
    if (!text) return;

    setError(null);
    setInput("");
    closeMention();
    setIsSending(true);

    setMessages((prev) => {
      const next: ChatMessage[] = [
        ...prev,
        { role: "user" as const, content: text },
        { role: "assistant" as const, content: "", meta: { used_llm: true } },
      ];
      assistantIndexRef.current = next.length - 1;
      return next;
    });

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const response = await chatApi.stream(buildPayload(text), controller.signal);
      if (!response.ok) {
        throw new Error("Failed to stream response.");
      }
      await readStream(response);
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === "AbortError") {
        return;
      }
      setError(err instanceof Error ? err.message : "Failed to send message.");
    } finally {
      setIsSending(false);
      abortRef.current = null;
      assistantIndexRef.current = null;
    }
  }

  function stopStreaming() {
    if (abortRef.current) {
      abortRef.current.abort();
    }
    setIsSending(false);
  }

  function clearFocus() {
    setManualContext(false);
    setActiveContext(baseContext);
  }

  const showBaseContext = !manualContext && (bugId || scanId || findingId);
  const showManualContext = manualContext && activeContext;

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-6">
      <div className="surface-solid p-6">
        <h1 className="text-2xl font-extrabold tracking-tight text-white">Chat</h1>
        <p className="mt-1 text-sm text-white/60">
          Ask ScanGuard AI about scans, findings, and triage recommendations. The
          assistant is grounded in your latest platform data.
        </p>
        {showBaseContext || showManualContext ? (
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-white/60">
            {showBaseContext ? (
              <>
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
              </>
            ) : null}
            {showManualContext ? (
              <>
                <span className="badge font-mono text-white/80">
                  focus {truncateLabel(activeContext.label, 48)}
                </span>
                <button type="button" className="btn-ghost" onClick={clearFocus}>
                  Clear focus
                </button>
              </>
            ) : null}
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
              <div className="space-y-2">
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  components={markdownComponents}
                  skipHtml
                >
                  {message.content}
                </ReactMarkdown>
              </div>

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
          <div className="relative">
            <textarea
              ref={inputRef}
              className="min-h-[92px] w-full resize-y rounded-card border-2 border-white/10 bg-void px-4 py-3 text-sm text-white placeholder-white/30 outline-none transition-colors duration-200 ease-fluid focus:border-neon-mint disabled:opacity-60"
              placeholder="Type your question... (use @ to mention a finding or bug)"
              value={input}
              onChange={(event) => {
                const value = event.target.value;
                setInput(value);
                updateMentionState(value, event.target.selectionStart ?? value.length);
              }}
              onKeyDown={handleKeyDown}
              disabled={isSending}
            />
            {mentionOpen ? (
              <div className="absolute left-0 right-0 top-full z-20 mt-2 rounded-card border border-white/10 bg-void shadow-[0_18px_40px_rgba(0,0,0,0.5)]">
                <div className="px-3 pt-2 text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                  Mention an issue
                </div>
                <div className="max-h-64 overflow-auto p-2">
                  {mentionSuggestions.length === 0 ? (
                    <div className="px-3 py-2 text-xs text-white/60">
                      No matches found.
                    </div>
                  ) : (
                    mentionSuggestions.map((item, index) => (
                      <button
                        key={`${item.type}-${item.id}`}
                        type="button"
                        className={`flex w-full flex-col gap-1 rounded-card px-3 py-2 text-left transition-colors ${
                          index === mentionIndex
                            ? "bg-white/10"
                            : "hover:bg-white/5"
                        }`}
                        onMouseDown={(event) => event.preventDefault()}
                        onClick={() => handleSelectMention(item)}
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="badge">{item.type}</span>
                          <span className="text-sm font-semibold text-white">
                            {truncateLabel(item.label)}
                          </span>
                        </div>
                        <div className="text-xs text-white/60">{item.subtitle}</div>
                      </button>
                    ))
                  )}
                </div>
              </div>
            ) : null}
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-xs text-white/60">
              Endpoint: <span className="font-mono text-white/80">/api/chat/stream</span>{" "}
              <span className="badge ml-2 border-neon-mint/40 bg-neon-mint/10 text-neon-mint">
                Live tokens
              </span>
            </div>
            <button
              type={isSending ? "button" : "submit"}
              disabled={!canSend && !isSending}
              className="btn-primary h-10 px-4"
              onClick={isSending ? stopStreaming : undefined}
              aria-label={isSending ? "Stop" : "Send"}
            >
              {isSending ? <Square size={16} /> : "Send"}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
