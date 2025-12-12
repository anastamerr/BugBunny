import { ReactNode } from "react";

type Props = {
  title: string;
  value: ReactNode;
  subtitle?: string;
  icon?: ReactNode;
};

export function StatsCard({ title, value, subtitle, icon }: Props) {
  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium text-gray-600">{title}</div>
        {icon}
      </div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
      {subtitle && <div className="mt-1 text-xs text-gray-500">{subtitle}</div>}
    </div>
  );
}

