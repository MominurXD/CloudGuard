export type Finding = {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  score: number;
  category: string;
  actor: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  summary: string;
  evidence: SecurityEvent[];
  recommended_actions: string[];
};

export type SecurityEvent = {
  timestamp: string;
  event_type: string;
  actor: string;
  source_ip: string;
  country: string;
  resource: string;
  status: string;
  metadata: Record<string, unknown>;
};

export type Dashboard = {
  summary: {
    events: number;
    findings: number;
    critical: number;
    high: number;
    medium: number;
    successful_events: number;
    failed_events: number;
    top_risky_actor: string | null;
    countries_seen: number;
    risk_score: number;
  };
  findings: Finding[];
  events: SecurityEvent[];
};

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000/api/v1";

export async function getDashboard(): Promise<Dashboard> {
  const response = await fetch(`${API_URL}/dashboard`);
  if (!response.ok) throw new Error("Unable to load security dashboard");
  return response.json();
}

export async function uploadAuditLog(file: File): Promise<Dashboard> {
  const body = new FormData();
  body.append("file", file);
  const response = await fetch(`${API_URL}/dashboard/upload`, { method: "POST", body });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(detail.detail ?? "Unable to analyse audit log");
  }
  return response.json();
}
