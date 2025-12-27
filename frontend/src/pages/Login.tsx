import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";

import { useAuth } from "../hooks/useAuth";

export default function Login() {
  const { signIn, user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (user) {
      const target = (location.state as { from?: string })?.from ?? "/";
      navigate(target, { replace: true });
    }
  }, [user, location.state, navigate]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setIsSubmitting(true);
    const message = await signIn(email.trim(), password);
    setIsSubmitting(false);
    if (message) {
      setError(message);
    }
  }

  return (
    <div className="relative min-h-screen bg-void text-white">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 overflow-hidden"
      >
        <div className="absolute -top-40 right-12 h-[420px] w-[420px] rounded-full bg-neon-mint/15 blur-3xl" />
        <div className="absolute bottom-0 left-0 h-[520px] w-[520px] rounded-full bg-white/5 blur-3xl" />
      </div>

      <div className="relative mx-auto flex min-h-screen w-full max-w-6xl items-center justify-center px-6 py-12">
        <div className="grid w-full gap-8 lg:grid-cols-[1.2fr_0.8fr]">
          <div className="surface-solid p-8">
            <div className="flex items-center gap-4">
              <img
                src="/icon.png"
                alt="ScanGuard AI logo"
                className="h-12 w-12 rounded-card border border-white/10 bg-white/5 p-2"
              />
              <div>
                <div className="text-xs font-semibold uppercase tracking-[0.25em] text-white/60">
                  ScanGuard AI
                </div>
                <h1 className="mt-1 text-2xl font-extrabold tracking-tight text-white">
                  Welcome back
                </h1>
              </div>
            </div>

            <p className="mt-4 text-sm text-white/60">
              Sign in to keep your repositories organized and your scan history
              private.
            </p>

            <form className="mt-6 space-y-4" onSubmit={handleSubmit}>
              <div>
                <label className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                  Email
                </label>
                <input
                  className="input mt-2 w-full"
                  type="email"
                  autoComplete="email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  required
                />
              </div>
              <div>
                <label className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                  Password
                </label>
                <input
                  className="input mt-2 w-full"
                  type="password"
                  autoComplete="current-password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                />
              </div>
              {error ? (
                <div className="rounded-card border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
                  {error}
                </div>
              ) : null}
              <button
                type="submit"
                className="btn-primary w-full"
                disabled={isSubmitting}
              >
                {isSubmitting ? "Signing in…" : "Sign in"}
              </button>
            </form>

            <div className="mt-6 text-sm text-white/60">
              New here?{" "}
              <Link className="text-neon-mint hover:text-neon-mint/80" to="/register">
                Create an account
              </Link>
            </div>
          </div>

          <div className="surface p-8">
            <div className="text-sm font-semibold uppercase tracking-[0.2em] text-white/60">
              What you get
            </div>
            <ul className="mt-4 space-y-3 text-sm text-white/70">
              <li>Saved repository watchlists per user.</li>
              <li>Context-aware triage with LLM reasoning.</li>
              <li>Private scan history and findings.</li>
              <li>One-click scans for your tracked repos.</li>
            </ul>
            <div className="mt-6 rounded-card border border-white/10 bg-white/5 p-4 text-xs text-white/60">
              Tip: connect your GitHub webhook to keep scans synced with pushes
              and pull requests.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
