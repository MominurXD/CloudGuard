import type { ReactNode } from "react";

type Props = { label: string; value: string; detail: string; icon: ReactNode };

export function StatCard({ label, value, detail, icon }: Props) {
  return (
    <article className="stat-card">
      <div className="stat-icon">{icon}</div>
      <div>
        <p className="eyebrow">{label}</p>
        <h3>{value}</h3>
        <p className="muted">{detail}</p>
      </div>
    </article>
  );
}
