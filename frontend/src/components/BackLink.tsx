import { Link } from "react-router-dom";
import { ArrowLeft } from "lucide-react";

type BackLinkProps = {
  to: string;
  label?: string;
  className?: string;
};

export function BackLink({ to, label = "Back", className = "" }: BackLinkProps) {
  return (
    <Link
      to={to}
      className={`inline-flex items-center gap-2 text-sm font-semibold text-white transition-colors duration-150 hover:text-neon-mint ${className}`}
    >
      <ArrowLeft className="h-4 w-4" />
      <span className="truncate">{label}</span>
    </Link>
  );
}
