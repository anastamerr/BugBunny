import type { ReactNode } from "react";

type LoadingStateProps = {
  variant?: "card" | "table" | "detail" | "inline";
  count?: number;
  className?: string;
};

function SkeletonCard() {
  return (
    <div className="surface-solid animate-pulse p-5">
      <div className="flex items-center gap-3">
        <div className="h-5 w-20 rounded-pill bg-white/10" />
        <div className="h-5 w-12 rounded-pill bg-white/5" />
      </div>
      <div className="mt-3 h-5 w-48 rounded-pill bg-white/10" />
      <div className="mt-2 h-4 w-32 rounded-pill bg-white/5" />
    </div>
  );
}

function SkeletonTableRow() {
  return (
    <tr>
      <td className="px-4 py-4">
        <div className="h-4 w-40 rounded-pill bg-white/10" />
      </td>
      <td className="px-4 py-4">
        <div className="h-4 w-24 rounded-pill bg-white/5" />
      </td>
      <td className="px-4 py-4">
        <div className="h-5 w-16 rounded-pill bg-white/10" />
      </td>
      <td className="px-4 py-4">
        <div className="h-4 w-20 rounded-pill bg-white/5" />
      </td>
      <td className="px-4 py-4">
        <div className="h-5 w-16 rounded-pill bg-white/10" />
      </td>
    </tr>
  );
}

function SkeletonDetail() {
  return (
    <div className="space-y-6">
      <div className="surface-solid animate-pulse p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div className="min-w-0 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="h-5 w-16 rounded-pill bg-white/10" />
              <div className="h-5 w-12 rounded-pill bg-white/5" />
              <div className="h-5 w-20 rounded-pill bg-white/10" />
            </div>
            <div className="h-6 w-80 rounded-pill bg-white/10" />
            <div className="h-3 w-48 rounded-pill bg-white/5" />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="h-9 w-20 rounded-pill bg-white/10" />
            <div className="h-9 w-20 rounded-pill bg-white/10" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={`detail-stat-${i}`} className="surface-solid animate-pulse p-5">
            <div className="h-3 w-28 rounded-pill bg-white/5" />
            <div className="mt-3 h-6 w-16 rounded-pill bg-white/10" />
          </div>
        ))}
      </div>
    </div>
  );
}

function SkeletonInline() {
  return (
    <div className="flex items-center gap-3 py-2">
      <div className="h-4 w-4 animate-pulse rounded-full bg-white/10" />
      <div className="h-4 w-32 animate-pulse rounded-pill bg-white/10" />
    </div>
  );
}

const variantMap: Record<string, () => ReactNode> = {
  card: () => <SkeletonCard />,
  table: () => <SkeletonTableRow />,
  detail: () => <SkeletonDetail />,
  inline: () => <SkeletonInline />,
};

export function LoadingState({
  variant = "card",
  count = 3,
  className = "",
}: LoadingStateProps) {
  const render = variantMap[variant];

  if (variant === "detail") {
    return <div className={className}>{render()}</div>;
  }

  if (variant === "table") {
    return (
      <tbody className={`animate-pulse ${className}`}>
        {Array.from({ length: count }).map((_, i) => (
          <SkeletonTableRow key={`skeleton-row-${i}`} />
        ))}
      </tbody>
    );
  }

  return (
    <div className={`space-y-4 ${className}`}>
      {Array.from({ length: count }).map((_, i) => (
        <div key={`skeleton-${i}`}>{render()}</div>
      ))}
    </div>
  );
}
