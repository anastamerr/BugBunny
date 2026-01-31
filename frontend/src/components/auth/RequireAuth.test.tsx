import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";

import { RequireAuth } from "./RequireAuth";

// Mock the useAuth hook
vi.mock("../../hooks/useAuth", () => ({
  useAuth: vi.fn(),
}));

// Get the mocked module
import { useAuth } from "../../hooks/useAuth";
const mockUseAuth = vi.mocked(useAuth);

describe("RequireAuth", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Clear env vars
    delete import.meta.env.VITE_DEV_AUTH_BYPASS;
    delete import.meta.env.VITE_DEV_BEARER_TOKEN;
  });

  it("shows loading state when auth is loading", () => {
    mockUseAuth.mockReturnValue({
      user: null,
      loading: true,
      supabase: null as any,
    });

    render(
      <MemoryRouter>
        <RequireAuth>
          <div>Protected Content</div>
        </RequireAuth>
      </MemoryRouter>
    );

    expect(screen.getByText("Loading session…")).toBeInTheDocument();
    expect(screen.queryByText("Protected Content")).not.toBeInTheDocument();
  });

  it("redirects to login when user is null and no dev bypass", () => {
    mockUseAuth.mockReturnValue({
      user: null,
      loading: false,
      supabase: null as any,
    });

    const { container } = render(
      <MemoryRouter initialEntries={["/scans"]}>
        <RequireAuth>
          <div>Protected Content</div>
        </RequireAuth>
      </MemoryRouter>
    );

    // Should not render children when not authenticated
    expect(screen.queryByText("Protected Content")).not.toBeInTheDocument();
  });

  it("renders children when user is authenticated", () => {
    mockUseAuth.mockReturnValue({
      user: { id: "user-123", email: "test@example.com" } as any,
      loading: false,
      supabase: null as any,
    });

    render(
      <MemoryRouter>
        <RequireAuth>
          <div>Protected Content</div>
        </RequireAuth>
      </MemoryRouter>
    );

    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("bypasses auth when VITE_DEV_AUTH_BYPASS is true", () => {
    mockUseAuth.mockReturnValue({
      user: null,
      loading: false,
      supabase: null as any,
    });

    // Set dev bypass env var
    import.meta.env.VITE_DEV_AUTH_BYPASS = "true";

    render(
      <MemoryRouter>
        <RequireAuth>
          <div>Protected Content</div>
        </RequireAuth>
      </MemoryRouter>
    );

    // Should render children even without user when dev bypass is enabled
    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("bypasses auth when VITE_DEV_BEARER_TOKEN is set", () => {
    mockUseAuth.mockReturnValue({
      user: null,
      loading: false,
      supabase: null as any,
    });

    // Set dev bearer token env var
    import.meta.env.VITE_DEV_BEARER_TOKEN = "some-token";

    render(
      <MemoryRouter>
        <RequireAuth>
          <div>Protected Content</div>
        </RequireAuth>
      </MemoryRouter>
    );

    // Should render children even without user when dev token is set
    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("handles VITE_DEV_AUTH_BYPASS case insensitively", () => {
    mockUseAuth.mockReturnValue({
      user: null,
      loading: false,
      supabase: null as any,
    });

    // Set dev bypass env var with uppercase
    import.meta.env.VITE_DEV_AUTH_BYPASS = "TRUE";

    render(
      <MemoryRouter>
        <RequireAuth>
          <div>Protected Content</div>
        </RequireAuth>
      </MemoryRouter>
    );

    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("does not bypass auth when VITE_DEV_AUTH_BYPASS is false", () => {
    mockUseAuth.mockReturnValue({
      user: null,
      loading: false,
      supabase: null as any,
    });

    // Explicitly set to false
    import.meta.env.VITE_DEV_AUTH_BYPASS = "false";

    render(
      <MemoryRouter>
        <RequireAuth>
          <div>Protected Content</div>
        </RequireAuth>
      </MemoryRouter>
    );

    // Should NOT render children when bypass is explicitly false
    expect(screen.queryByText("Protected Content")).not.toBeInTheDocument();
  });
});
