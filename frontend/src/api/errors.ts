import axios from "axios";

const API_BASE = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(
  /\/+$/,
  "",
);

type ErrorDetails = {
  message: string;
  suggestion?: string;
  status?: number;
  detail?: string | null;
};

export class ApiError extends Error {
  status?: number;
  suggestion?: string;
  detail?: string | null;

  constructor(details: ErrorDetails, cause?: unknown) {
    const message = details.suggestion
      ? `${details.message} Try: ${details.suggestion}`
      : details.message;
    super(message);
    this.name = "ApiError";
    this.status = details.status;
    this.suggestion = details.suggestion;
    this.detail = details.detail ?? null;
    if (cause) {
      (this as { cause?: unknown }).cause = cause;
    }
  }
}

const statusHints: Record<number, Pick<ErrorDetails, "message" | "suggestion">> =
  {
    400: {
      message: "We could not process that request.",
      suggestion: "Check the inputs and try again.",
    },
    401: {
      message: "Your session is not valid.",
      suggestion: "Sign in again and retry.",
    },
    403: {
      message: "You do not have access to this action.",
      suggestion: "Request access or use a different account.",
    },
    404: {
      message: "We could not find what you requested.",
      suggestion: "Check the link or refresh and try again.",
    },
    409: {
      message: "This request conflicts with existing data.",
      suggestion: "Refresh and retry the action.",
    },
    422: {
      message: "Some input values are invalid.",
      suggestion: "Review the form fields and try again.",
    },
    429: {
      message: "Too many requests in a short time.",
      suggestion: "Wait a moment and retry.",
    },
    500: {
      message: "The server hit an error.",
      suggestion: "Try again or check the backend logs.",
    },
    502: {
      message: "The server is unavailable.",
      suggestion: "Make sure the backend is running and try again.",
    },
    503: {
      message: "The server is temporarily unavailable.",
      suggestion: "Retry in a moment.",
    },
    504: {
      message: "The server took too long to respond.",
      suggestion: "Try again or check your connection.",
    },
  };

const detailHints: Array<{
  match: RegExp;
  message: string;
  suggestion?: string;
}> = [
  {
    match: /missing authorization header/i,
    message: "You are not signed in.",
    suggestion: "Sign in and retry.",
  },
  {
    match: /invalid authorization header/i,
    message: "We could not read your sign-in token.",
    suggestion: "Sign out and sign in again.",
  },
  {
    match: /missing bearer token/i,
    message: "Your session is missing a token.",
    suggestion: "Sign in again.",
  },
  {
    match: /invalid or expired token/i,
    message: "Your session has expired.",
    suggestion: "Sign in again.",
  },
  {
    match: /token is missing subject|token subject is invalid/i,
    message: "Your session token is invalid.",
    suggestion: "Sign in again.",
  },
  {
    match: /supabase_jwt_secret is not configured/i,
    message: "Authentication is not configured on the server.",
    suggestion: "Set SUPABASE_JWT_SECRET in the backend config.",
  },
  {
    match: /repository url is required/i,
    message: "Repository URL is required.",
    suggestion: "Paste a GitHub repository URL and try again.",
  },
  {
    match: /repository not found/i,
    message: "Repository not found.",
    suggestion: "Check the URL and ensure you have access.",
  },
  {
    match: /scan not found/i,
    message: "Scan not found.",
    suggestion: "Refresh the page and try again.",
  },
  {
    match: /finding not found/i,
    message: "Finding not found.",
    suggestion: "Refresh the page and try again.",
  },
  {
    match: /bug not found/i,
    message: "Bug not found.",
    suggestion: "Refresh the page and try again.",
  },
  {
    match: /target_url is required/i,
    message: "Target URL is required for DAST scans.",
    suggestion: "Enter a live URL or switch to SAST.",
  },
  {
    match: /repo_url is required/i,
    message: "Repository URL is required for SAST scans.",
    suggestion: "Enter a repository URL or switch to DAST.",
  },
  {
    match: /invalid payload/i,
    message: "We could not read the request payload.",
    suggestion: "Check the form inputs and try again.",
  },
];

function extractDetail(data: unknown): string | null {
  if (!data) return null;
  if (typeof data === "string") return data;
  if (typeof Blob !== "undefined" && data instanceof Blob) return null;
  if (typeof data !== "object") return null;

  const record = data as Record<string, unknown>;
  const detail = record.detail ?? record.message ?? record.error;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => (typeof item?.msg === "string" ? item.msg : null))
      .filter(Boolean);
    return messages.length ? messages.join(" ") : null;
  }
  return null;
}

function mapDetail(detail: string): Pick<ErrorDetails, "message" | "suggestion"> {
  for (const hint of detailHints) {
    if (hint.match.test(detail)) {
      return { message: hint.message, suggestion: hint.suggestion };
    }
  }
  return { message: detail };
}

function buildError(details: ErrorDetails, cause?: unknown): ApiError {
  return new ApiError(details, cause);
}

export function toApiError(err: unknown): ApiError {
  if (err instanceof ApiError) return err;

  if (axios.isAxiosError(err)) {
    const status = err.response?.status;
    const detail = extractDetail(err.response?.data);

    if (!err.response) {
      const message =
        err.code === "ECONNABORTED"
          ? "The request timed out."
          : "We could not reach the server.";
      return buildError(
        {
          message,
          suggestion: `Check that the API is running at ${API_BASE}.`,
        },
        err,
      );
    }

    const hint = status ? statusHints[status] : undefined;
    const detailHint = detail ? mapDetail(detail) : undefined;

    return buildError(
      {
        message: detailHint?.message || hint?.message || "Request failed.",
        suggestion: detailHint?.suggestion || hint?.suggestion,
        status,
        detail,
      },
      err,
    );
  }

  return buildError(
    { message: "Something went wrong.", suggestion: "Try again." },
    err,
  );
}

export async function toApiErrorFromResponse(
  response: Response,
): Promise<ApiError> {
  let detail: string | null = null;
  const contentType = response.headers.get("content-type") || "";

  try {
    if (contentType.includes("application/json")) {
      const data = await response.json();
      detail = extractDetail(data);
    } else {
      const text = await response.text();
      detail = text || null;
    }
  } catch {
    detail = null;
  }

  const status = response.status;
  const hint = statusHints[status];
  const detailHint = detail ? mapDetail(detail) : undefined;

  return buildError({
    message: detailHint?.message || hint?.message || "Request failed.",
    suggestion: detailHint?.suggestion || hint?.suggestion,
    status,
    detail,
  });
}
