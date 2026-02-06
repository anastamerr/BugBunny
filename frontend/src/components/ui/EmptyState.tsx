import type { ReactNode } from "react";

type EmptyStateProps = {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
};

export function EmptyState({
  icon,
  title,
  description,
  action,
  className = "",
}: EmptyStateProps) {
  return (
    <div className={`empty-state surface-solid ${className}`}>
      {icon ? <div className="empty-state-icon">{icon}</div> : null}
      <h3 className="empty-state-title">{title}</h3>
      {description ? (
        <p className="empty-state-description">{description}</p>
      ) : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}
