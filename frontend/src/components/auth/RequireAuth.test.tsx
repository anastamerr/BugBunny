import { cleanup, render, screen } from "@testing-library/react";
import type { User } from "@supabase/supabase-js";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the useAuth hook
vi.mock("../../hooks/useAuth", () => ({
  useAuth: vi.fn(),
}));

// Get the mocked module
import { useAuth } from "../../hooks/useAuth";
const mockUseAuth = vi.mocked(useAuth);
let RequireAuth: typeof import("./RequireAuth").RequireAuth;

const baseAuth = {
  session: null,
  user: null,
  loading: false,
  signIn: vi.fn(async () => null),
  signUp: vi.fn(async () => null),
  signOut: vi.fn(async () => undefined),
};

describe("RequireAuth", () => {
  beforeAll(async () => {
    ({ RequireAuth } = await import("./RequireAuth"));
  });

  beforeEach(() => {
    vi.restoreAllMocks();
    import.meta.env.VITE_DEV_AUTH_BYPASS = "false";
    delete import.meta.env.VITE_DEV_BEARER_TOKEN;
  });

  afterEach(() => {
    cleanup();
  });

  it("shows loading state when auth is loading", () => {
    mockUseAuth.mockReturnValue({
      ...baseAuth,
      loading: true,
    });

    render(
      <MemoryRouter initialEntries={["/scans"]}>
        <Routes>
          <Route
            path="/scans"
            element={
              <RequireAuth>
                <div>Protected Content</div>
              </RequireAuth>
            }
          />
          <Route path="/login" element={<div>Login</div>} />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText("Loading session...")).toBeInTheDocument();
    expect(screen.queryByText("Protected Content")).not.toBeInTheDocument();
  });

  it("redirects to login when user is null and no dev bypass", () => {
    mockUseAuth.mockReturnValue({
      ...baseAuth,
    });

    render(
      <MemoryRouter initialEntries={["/scans"]}>
        <Routes>
          <Route
            path="/scans"
            element={
              <RequireAuth>
                <div>Protected Content</div>
              </RequireAuth>
            }
          />
          <Route path="/login" element={<div>Login</div>} />
        </Routes>
      </MemoryRouter>
    );

    // Should not render children when not authenticated
    expect(screen.queryByText("Protected Content")).not.toBeInTheDocument();
  });

  it("renders children when user is authenticated", () => {
    mockUseAuth.mockReturnValue({
      ...baseAuth,
      user: { id: "user-123", email: "test@example.com" } as unknown as User,
    });

    render(
      <MemoryRouter initialEntries={["/scans"]}>
        <Routes>
          <Route
            path="/scans"
            element={
              <RequireAuth>
                <div>Protected Content</div>
              </RequireAuth>
            }
          />
          <Route path="/login" element={<div>Login</div>} />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("bypasses auth when VITE_DEV_AUTH_BYPASS is true", () => {
    mockUseAuth.mockReturnValue({
      ...baseAuth,
    });

    import.meta.env.VITE_DEV_AUTH_BYPASS = "true";

    render(
      <MemoryRouter initialEntries={["/scans"]}>
        <Routes>
          <Route
            path="/scans"
            element={
              <RequireAuth>
                <div>Protected Content</div>
              </RequireAuth>
            }
          />
          <Route path="/login" element={<div>Login</div>} />
        </Routes>
      </MemoryRouter>
    );

    // Should render children even without user when dev bypass is enabled
    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("bypasses auth when VITE_DEV_BEARER_TOKEN is set", () => {
    mockUseAuth.mockReturnValue({
      ...baseAuth,
    });

    import.meta.env.VITE_DEV_BEARER_TOKEN = "some-token";

    render(
      <MemoryRouter initialEntries={["/scans"]}>
        <Routes>
          <Route
            path="/scans"
            element={
              <RequireAuth>
                <div>Protected Content</div>
              </RequireAuth>
            }
          />
          <Route path="/login" element={<div>Login</div>} />
        </Routes>
      </MemoryRouter>
    );

    // Should render children even without user when dev token is set
    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("handles VITE_DEV_AUTH_BYPASS case insensitively", () => {
    mockUseAuth.mockReturnValue({
      ...baseAuth,
    });

    import.meta.env.VITE_DEV_AUTH_BYPASS = "TRUE";

    render(
      <MemoryRouter initialEntries={["/scans"]}>
        <Routes>
          <Route
            path="/scans"
            element={
              <RequireAuth>
                <div>Protected Content</div>
              </RequireAuth>
            }
          />
          <Route path="/login" element={<div>Login</div>} />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("does not bypass auth when VITE_DEV_AUTH_BYPASS is false", () => {
    mockUseAuth.mockReturnValue({
      ...baseAuth,
    });

    import.meta.env.VITE_DEV_AUTH_BYPASS = "false";

    render(
      <MemoryRouter initialEntries={["/scans"]}>
        <Routes>
          <Route
            path="/scans"
            element={
              <RequireAuth>
                <div>Protected Content</div>
              </RequireAuth>
            }
          />
          <Route path="/login" element={<div>Login</div>} />
        </Routes>
      </MemoryRouter>
    );

    // Should NOT render children when bypass is explicitly false
    expect(screen.queryByText("Protected Content")).not.toBeInTheDocument();
  });
});
