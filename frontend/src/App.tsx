import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, AlertTriangle, FileUp, Globe2, Shield, ShieldAlert, UserRoundSearch } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { StatCard } from "./components/StatCard";
import { Dashboard, Finding, getDashboard, uploadAuditLog } from "./lib/api";

const fmt = new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });

function severityRank(value: string) {
  return value === "critical" ? 4 : value === "high" ? 3 : value === "medium" ? 2 : 1;
}

export default function App() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    getDashboard().then((payload) => { setData(payload); setSelected(payload.findings[0] ?? null); }).catch((e) => setError(e.message)).finally(() => setLoading(false));
  }, []);

  const severityData = useMemo(() => {
    if (!data) return [];
    return [
      { severity: "Critical", count: data.summary.critical },
      { severity: "High", count: data.summary.high },
      { severity: "Medium", count: data.summary.medium },
    ];
  }, [data]);

  async function handleUpload(file?: File) {
    if (!file) return;
    setLoading(true); setError("");
    try {
      const payload = await uploadAuditLog(file);
      setData(payload); setSelected(payload.findings[0] ?? null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally { setLoading(false); }
  }

  if (loading && !data) return <main className="center">Analysing cloud audit activity…</main>;
  if (!data) return <main className="center">{error || "Dashboard unavailable"}</main>;

  const findings = [...data.findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  return (
    <main className="shell">
      <header className="hero">
        <div>
          <div className="brand"><Shield size={28} /> CloudGuard</div>
          <p className="eyebrow">Cloud security operations</p>
          <h1>Detect suspicious cloud activity before it becomes an incident.</h1>
          <p className="lede">A defensive security analytics platform for triaging identity, IAM, storage and network exposure events.</p>
        </div>
        <div>
          <input ref={inputRef} hidden type="file" accept=".json" onChange={(e) => handleUpload(e.target.files?.[0])} />
          <button onClick={() => inputRef.current?.click()}><FileUp size={18}/> Analyse audit log</button>
        </div>
      </header>

      {error && <div className="error">{error}</div>}

      <section className="stats">
        <StatCard label="Risk score" value={`${data.summary.risk_score}/100`} detail="Based on detected findings" icon={<ShieldAlert />} />
        <StatCard label="Critical findings" value={String(data.summary.critical)} detail={`${data.summary.findings} total findings`} icon={<AlertTriangle />} />
        <StatCard label="Audit events" value={data.summary.events.toLocaleString()} detail={`${data.summary.failed_events} failed events`} icon={<Activity />} />
        <StatCard label="Countries seen" value={String(data.summary.countries_seen)} detail={data.summary.top_risky_actor ?? "No risky actor"} icon={<Globe2 />} />
      </section>

      <section className="grid">
        <article className="panel findings-panel">
          <div className="panel-head"><div><p className="eyebrow">Detection queue</p><h2>Security findings</h2></div><span>{findings.length}</span></div>
          <div className="findings-list">
            {findings.map((finding) => (
              <button className={`finding-row ${selected?.id === finding.id ? "active" : ""}`} key={finding.id} onClick={() => setSelected(finding)}>
                <div><span className={`badge ${finding.severity}`}>{finding.severity}</span><strong>{finding.title}</strong></div>
                <p>{finding.summary}</p>
                <small>{finding.actor} · {fmt.format(new Date(finding.last_seen))}</small>
              </button>
            ))}
          </div>
        </article>

        <article className="panel detail-panel">
          {selected ? <>
            <div className="panel-head"><div><p className="eyebrow">Incident investigation</p><h2>{selected.title}</h2></div><span className={`badge ${selected.severity}`}>{selected.severity}</span></div>
            <p className="summary-copy">{selected.summary}</p>
            <div className="meta-grid">
              <div><span>Actor</span><strong>{selected.actor}</strong></div>
              <div><span>Category</span><strong>{selected.category}</strong></div>
              <div><span>Risk score</span><strong>{selected.score}/100</strong></div>
              <div><span>Events</span><strong>{selected.event_count}</strong></div>
            </div>
            <h3>Recommended response</h3>
            <ol className="actions">{selected.recommended_actions.map((action) => <li key={action}>{action}</li>)}</ol>
            <h3>Evidence timeline</h3>
            <div className="timeline">{selected.evidence.map((event, i) => <div className="timeline-row" key={`${event.timestamp}-${i}`}><span></span><div><strong>{event.event_type}</strong><p>{event.actor} from {event.source_ip} ({event.country}) · {event.status}</p><small>{fmt.format(new Date(event.timestamp))}</small></div></div>)}</div>
          </> : <p className="muted">Select a finding to investigate.</p>}
        </article>
      </section>

      <section className="grid lower">
        <article className="panel">
          <p className="eyebrow">Severity profile</p><h2>Open finding distribution</h2>
          <div className="chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={severityData}><CartesianGrid strokeDasharray="3 3" vertical={false}/><XAxis dataKey="severity"/><YAxis allowDecimals={false}/><Tooltip/><Bar dataKey="count" /></BarChart></ResponsiveContainer></div>
        </article>
        <article className="panel">
          <div className="panel-head"><div><p className="eyebrow">Recent activity</p><h2>Audit event stream</h2></div><UserRoundSearch /></div>
          <div className="events">{data.events.slice(0, 8).map((event, i) => <div className="event-row" key={`${event.timestamp}-${i}`}><div><strong>{event.event_type}</strong><p>{event.actor} · {event.resource}</p></div><div className="event-side"><span className={event.status === "Failure" ? "failed" : "success"}>{event.status}</span><small>{event.country} · {fmt.format(new Date(event.timestamp))}</small></div></div>)}</div>
        </article>
      </section>
    </main>
  );
}
