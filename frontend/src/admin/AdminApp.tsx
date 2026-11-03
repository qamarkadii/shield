import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import MapFrame from '../components/MapFrame';
import { api, post, LEVEL, tone, pct, type Alert, type CheckResult, type Detection, type EvidencePack, type Investigation, type ModelStatus, type PageCheck, type Radar, type Stats } from './api';
import logo from '../assets/aida-logo.png';

/* ---------- small hooks & helpers ---------- */
function usePoll<T>(path: string, every: number, deps: unknown[] = []): [T | null, () => void, string] {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const load = useCallback(() => { api<T>(path).then(d => { setData(d); setError(''); }).catch(e => setError(e.message)); }, [path]);
  useEffect(() => { load(); const id = setInterval(load, every); return () => clearInterval(id); }, [load, every, ...deps]); // eslint-disable-line react-hooks/exhaustive-deps
  return [data, load, error];
}
const Score = ({ v, s }: { v?: string; s: number | null | undefined }) => <span className={`score-chip ${tone(v)}`}>{s ?? '—'}</span>;
function KV({ rows }: { rows: [string, ReactNode][] }) {
  return <dl className="kv">{rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v === null || v === undefined || v === '' ? '—' : v}</dd></div>)}</dl>;
}
function List({ title, items }: { title: string; items?: string[] }) {
  if (!items || !items.length) return null;
  return <><p className="mono list-title">{title}</p><ul className="reasons">{items.map((x, i) => <li key={i}>{x}</li>)}</ul></>;
}
function Panel({ title, sub, actions, children, className = '' }: { title: string; sub?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`panel glass ${className}`}><header className="panel-head"><h2>{title}{sub && <span className="mono muted"> {sub}</span>}</h2>{actions}</header><div className="panel-body">{children}</div></section>;
}

/* ---------- toast + confirm ---------- */
type Toast = { id: number; text: string; bad?: boolean };
function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, bad = false) => { const id = Date.now() + Math.random(); setToasts(t => [...t, { id, text, bad }]); setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4500); }, []);
  return { toasts, push };
}
interface Ask { title: string; body: string; ok: string; resolve: (v: boolean) => void }
function ConfirmDialog({ ask, close }: { ask: Ask | null; close: (v: boolean) => void }) {
  const okRef = useRef<HTMLButtonElement>(null);
  useEffect(() => { if (ask) okRef.current?.focus(); }, [ask]);
  return <AnimatePresence>{ask && <motion.div className="modal-backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => close(false)}>
    <motion.div role="dialog" aria-modal="true" aria-labelledby="dlg-title" className="modal glass" initial={{ y: 12, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 12, opacity: 0 }} onClick={e => e.stopPropagation()} onKeyDown={e => { if (e.key === 'Escape') close(false); }}>
      <h3 id="dlg-title">{ask.title}</h3><p>{ask.body}</p>
      <div className="modal-actions"><button className="button secondary" onClick={() => close(false)}>Cancel</button><button ref={okRef} className="button primary" onClick={() => close(true)}>{ask.ok}</button></div>
    </motion.div></motion.div>}</AnimatePresence>;
}

/* ---------- header ---------- */
function publicSiteUrl() {
  const { protocol, hostname, port, pathname } = window.location;
  if (pathname.startsWith('/admin')) return '/';            // server: public site on the same address
  return port === '8000' ? `${protocol}//${hostname}:8001/` : '/';
}
function Header({ radar, onRadar, onReplay, busy }: { radar: Radar | null; onRadar: () => void; onReplay: () => void; busy: boolean }) {
  const live = !!radar?.running;
  return <header className="admin-header"><div className="admin-wrap nav">
    <div className="header-left"><span className="brand-sub">ANALYST CONSOLE</span><span className={`radar-pill ${live ? 'live' : ''}`}><i className="status-dot" />{live ? `Radar live · ${radar?.certs_per_second ?? 0}/s` : 'Radar off'}</span></div>
    <a className="brand-logo" href="./" aria-label="AIDA Shield analyst console"><img src={logo} alt="AIDA" width="720" height="205" /></a>
    <div className="header-actions">
      <button className={`button ${live ? 'secondary' : 'primary'} small`} onClick={onRadar}>{live ? 'Stop radar' : 'Start live radar'}</button>
      <button className="button secondary small" onClick={onReplay} disabled={busy}>Load real UAE cases</button>
      <a className="text-button" href={publicSiteUrl()} target="_blank" rel="noreferrer">Public site ↗</a>
    </div>
  </div></header>;
}

/* ---------- map band ---------- */
function OpsBand({ stats, radar, feed }: { stats: Stats | null; radar: Radar | null; feed: Detection[] | null }) {
  const [n, setN] = useState(0);
  const last = useRef(0);
  const onIntercept = useCallback(() => { const now = performance.now(); if (now - last.current > 3200) { last.current = now; setN(x => x + 1); } }, []);
  const latest = (feed ?? []).slice(0, 8);
  const d = latest.length ? latest[n % latest.length] : null;
  const live = !!radar?.running;
  return <section className="ops-band glass" aria-label="Threat map">
    <MapFrame compact arrows={live ? 10 : 6} speed={live ? 1.25 : 0.8} onIntercept={onIntercept} label="Threat map: red arrows are flagged domains converging on AIDA's Shield. Arrow origins are illustrative." />
    <div className="ops-left">
      <span className="eyebrow"><i className={`status-dot ${live ? '' : 'off'}`} />{live ? 'LIVE CERTIFICATE RADAR' : 'RADAR OFF'}</span>
      {stats ? <><strong className="ops-big">{(stats.certs_checked_now ?? 0).toLocaleString()}</strong><span className="mono muted">certificates checked this session{live ? ` · ${stats.certs_per_second ?? 0}/s` : ''}</span></> : <div className="skeleton sk-line wide" />}
    </div>
    <div className="core-pin small"><span className="mono">COMMAND CENTRE</span><h1>AIDA <span>Team</span></h1></div>
    {d && n > 0 && <div className="intercept-label glass" key={n}><i className={`status-dot ${d.verdict === 'high risk' ? 'red' : ''}`} /><span className="mono">{d.domain}</span><small>{LEVEL[d.verdict]} · score {d.score ?? '—'}{d.brand ? ` · ${d.brand}` : ''}</small></div>}
    <p className="mono ops-note">ARROWS = FLAGGED DOMAINS · ORIGINS ILLUSTRATIVE</p>
  </section>;
}

/* ---------- KPIs ---------- */
function Kpis({ stats }: { stats: Stats | null }) {
  const items: [string, number | undefined, string?][] = stats ? [
    ['UAE domains seen live', stats.uae_seen_now],
    ['Flagged domains', stats.flagged],
    ['High risk', stats.high_risk, 'red'],
    ['Citizen reports', stats.citizen_reports],
    ['Alerts sent', stats.alerts_sent],
    ['Analyst labels', stats.labels],
  ] : [];
  return <section className="kpis">{stats ? items.map(([k, v, c]) => <div className="kpi glass" key={k}><span className="mono muted">{k}</span><strong className={c}>{(v ?? 0).toLocaleString()}</strong></div>)
    : Array.from({ length: 6 }, (_, i) => <div className="kpi glass skeleton" key={i}><div className="sk-line" /><div className="sk-block" /></div>)}</section>;
}

/* ---------- detections ---------- */
const TABS: [string, string][] = [['', 'All flagged'], ['live', 'Live'], ['watch', 'UAE watch'], ['citizen', 'Citizen'], ['replay', 'Replay']];
function Detections({ rows, source, setSource, selected, onSelect, onLabel, onAlert }: { rows: Detection[] | null; source: string; setSource: (s: string) => void; selected: number | null; onSelect: (d: Detection) => void; onLabel: (d: Detection, yes: boolean) => void; onAlert: (d: Detection) => void }) {
  const [q, setQ] = useState('');
  const shown = useMemo(() => { const k = q.trim().toLowerCase(); return (rows ?? []).filter(d => !k || d.domain.includes(k) || (d.brand ?? '').toLowerCase().includes(k) || (d.note ?? '').toLowerCase().includes(k)); }, [rows, q]);
  const pending = (rows ?? []).filter(d => d.status === 'pending').length;
  return <Panel className="detections" title="Detections" sub={rows ? `· ${rows.length} shown · ${pending} awaiting review` : undefined}
    actions={<div className="det-tools"><div className="tabs" role="tablist">{TABS.map(([k, label]) => <button key={k} role="tab" aria-selected={source === k} className={source === k ? 'on' : ''} onClick={() => setSource(k)}>{label}</button>)}</div>
      <div className="input-shell search"><span aria-hidden="true">⌕</span><label className="sr-only" htmlFor="det-search">Filter detections</label><input id="det-search" value={q} onChange={e => setQ(e.target.value)} placeholder="Filter domains" /></div></div>}>
    <div className="table-wrap"><table>
      <thead><tr><th>Risk</th><th>Domain</th><th>Imitates</th><th>Source</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead>
      <tbody>
        {rows === null ? Array.from({ length: 6 }, (_, i) => <tr key={i} className="sk-row"><td colSpan={6}><div className="skeleton sk-line wide" /></td></tr>)
          : !shown.length ? <tr><td colSpan={6} className="empty">{rows.length ? 'Nothing matches this filter.' : 'No detections yet. Start the live radar, load the real UAE cases, or check a link.'}</td></tr>
          : shown.map(d => <tr key={d.id} className={`${selected === d.id ? 'selected' : ''} ${d.status}`} onClick={() => onSelect(d)} tabIndex={0} onKeyDown={e => { if (e.key === 'Enter') onSelect(d); }} aria-label={`Investigate ${d.domain}`}>
            <td><Score v={d.verdict} s={d.score} /><span className="lvl mono">{LEVEL[d.verdict] ?? d.verdict}</span></td>
            <td className="dom-cell"><span className="dom mono">{d.domain}</span><span className="why">{d.reasons?.[0] ?? (d.note ? `UAE watch: ${d.note}` : '')}</span></td>
            <td>{d.brand ?? <span className="muted">—</span>}</td>
            <td><span className={`tag ${d.source}`}>{d.source}</span></td>
            <td><span className={`status ${d.status}`}>{d.status === 'confirmed' ? 'Phishing' : d.status === 'legit' ? 'Legit' : 'Pending'}</span></td>
            <td className="row-actions" onClick={e => e.stopPropagation()}>
              <button className="chip-btn danger" onClick={() => onLabel(d, true)} title="Confirm as phishing">Phishing</button>
              <button className="chip-btn" onClick={() => onLabel(d, false)} title="Mark as legitimate">Legit</button>
              <button className="chip-btn alert" disabled={d.status === 'legit'} onClick={() => onAlert(d)}>Alert</button>
            </td>
          </tr>)}
      </tbody>
    </table></div>
  </Panel>;
}

/* ---------- investigation ---------- */
function InvestigationPanel({ d, onClose, onLabel, onAlert, toast }: { d: Detection; onClose: () => void; onLabel: (d: Detection, yes: boolean) => void; onAlert: (d: Detection) => void; toast: (t: string, bad?: boolean) => void }) {
  const [r, setR] = useState<Investigation | null>(null);
  const [err, setErr] = useState('');
  const [page, setPage] = useState<PageCheck | null>(null);
  const [pageBusy, setPageBusy] = useState(false);
  const [ev, setEv] = useState<EvidencePack | null>(null);
  const [evBusy, setEvBusy] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    setR(null); setErr(''); setPage(null); setEv(null);
    let stop = false;
    api<Investigation>(`/investigate?domain=${encodeURIComponent(d.domain)}`).then(x => { if (!stop) setR(x); }).catch(e => { if (!stop) setErr(e.message); });
    if (matchMedia('(max-width:1100px)').matches) ref.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    return () => { stop = true; };
  }, [d.id, d.domain]);
  const runPage = async () => {
    setPageBusy(true);
    try { setPage(await post<PageCheck>(`/pagecheck?domain=${encodeURIComponent(d.domain)}${d.url ? `&url=${encodeURIComponent(d.url)}` : ''}`)); }
    catch (e) { setPage({ error: (e as Error).message }); }
    setPageBusy(false);
  };
  const runEvidence = async () => {
    setEvBusy(true);
    try { setEv(d.id ? await post<EvidencePack>(`/detections/${d.id}/evidence`) : await post<EvidencePack>(`/evidence?domain=${encodeURIComponent(d.domain)}`)); toast('Evidence pack ready. The Alert button now attaches it.'); }
    catch (e) { toast(`Evidence error: ${(e as Error).message}`, true); }
    setEvBusy(false);
  };
  const fx = r?.facts ?? {}, rd = fx.rdap ?? {}, h = fx.hosting ?? {}, c = fx.certificate ?? {}, dn = fx.dns ?? {};
  return <div ref={ref}><Panel className="investigation" title="Investigation" sub={undefined} actions={<button className="text-button" onClick={onClose} aria-label="Close investigation">Close ✕</button>}>
    <p className="dom mono inv-domain">{d.domain}</p>
    <div className="inv-actions">
      <button className="chip-btn danger" onClick={() => onLabel(d, true)}>Confirm phishing</button>
      <button className="chip-btn" onClick={() => onLabel(d, false)}>Mark legit</button>
      <button className="chip-btn solid" disabled={d.status === 'legit'} onClick={() => onAlert(d)}>Send alert</button>
    </div>
    {err ? <p className="error">Lookup failed: {err}</p> : !r ? <div className="inv-loading"><div className="skeleton sk-block" /><p className="mono muted">Looking up registration, DNS, hosting and certificate… (5–15 s)</p></div> : <>
      <div className="inv-verdict"><Score v={r.verdict} s={r.score} /><div><strong>{LEVEL[r.verdict] ?? r.verdict}</strong>{r.name_verdict && r.name_verdict !== r.verdict && <span className="mono muted">Name alone: {LEVEL[r.name_verdict]} → with domain facts: {LEVEL[r.verdict]}</span>}</div></div>
      <KV rows={[
        ['Registered', rd.age_days !== undefined && rd.age_days !== null ? `${rd.created} (${rd.age_days} days ago)` : (rd.not_applicable || 'unknown (no public record)')],
        ['Registrar', rd.registrar], ['Registrar abuse', rd.registrar_abuse_email],
        ['Online', dn.resolves ? `yes · ${(dn.a ?? []).slice(0, 2).join(', ')}` : 'no (does not resolve)'],
        ['Hosting', h.ip ? `AS${h.asn} ${h.as_name ?? ''} (${h.country ?? '?'})` : null], ['Host abuse', h.abuse?.abuse_email],
        ['Certificate', c.https ? `${c.issuer} · issued ${c.issued_days_ago} days ago · ${c.names_covered} names` : c.https === false ? 'no working HTTPS' : null],
        ['Mail (MX)', (dn.mx ?? []).length ? 'yes' : 'no']]} />
      <List title="WHY" items={r.reasons} />
      <div className="inv-actions">
        <button className="button secondary small" onClick={runPage} disabled={pageBusy}>{pageBusy ? 'Opening… (up to 45 s)' : page ? 'Open page again' : 'Open page in isolated browser'}</button>
        <button className="button primary small" onClick={runEvidence} disabled={evBusy}>{evBusy ? 'Building pack… (up to 60 s)' : ev ? 'Rebuild evidence pack' : 'Make evidence pack'}</button>
      </div>
      <p className="small muted">The page opens only on the Shield server, in a throwaway browser that can't reach local addresses. Nothing is typed or clicked.</p>
      {page && <div className="inv-page">
        <p className="mono list-title">PAGE · {page.verdict ?? '—'}</p>
        {page.error && <p className="error">{page.error}</p>}
        <KV rows={[['Title', page.title], ['Asks for', Object.entries(page.asks_for ?? {}).filter(([, v]) => v).map(([k]) => k).join(', ') || 'nothing sensitive'],
          ['Claims to be', (page.claims_brand_off_domain ?? []).join(', ')], ['Looks like', (page.looks_like ?? []).map(x => `${x.brand} ${Math.round(x.similarity * 100)}%`).join(', ')], ['Final address', page.final_url]]} />
        <List title="PAGE WARNING SIGNS" items={page.signs} />
        {page.screenshot_url && <img src={`${page.screenshot_url}?t=${Date.now()}`} alt="Screenshot taken by the isolated browser" />}
      </div>}
      {ev && <div className="inv-page">
        <p className="mono list-title">EVIDENCE PACK READY</p>
        <a className="text-link cyan" href={ev.report_path.replace(/^\//, '')} target="_blank" rel="noreferrer">Open report, screenshot and takedown e-mails (English + Arabic) ↗</a>
        <List title="SEND TAKEDOWN REQUESTS TO" items={(ev.abuse_contacts ?? []).map(x => `${x.who}: ${x.email}`)} />
        <p className="small muted">SHA-256 {ev.evidence_sha256}</p>
      </div>}
    </>}
  </Panel></div>;
}

/* ---------- quick check ---------- */
function QuickCheck({ onDone }: { onDone: () => void }) {
  const [v, setV] = useState('');
  const [busy, setBusy] = useState(false);
  const [r, setR] = useState<CheckResult | null>(null);
  const [err, setErr] = useState('');
  const run = async () => {
    if (!v.trim()) return; setBusy(true); setErr('');
    try { setR(await post<CheckResult>('/report', { url: v.trim() })); onDone(); } catch (e) { setR(null); setErr((e as Error).message); }
    setBusy(false);
  };
  const strip = (a?: string[]) => (a ?? []).map(x => x.replace(/^(Fact|Rule): /, ''));
  const sc = r?.score === null || r?.score === undefined ? '' : ` · risk ${r.score}/100`;
  const title = r ? ({ official: `Verified official${r.brand ? ` · ${r.brand}` : ''}`, 'high risk': `High risk${sc}`, suspicious: `Suspicious${sc}`, unknown: "Unknown · Shield can't verify this link", 'no warning signs': `No warning signs${sc}` } as Record<string, string>)[r.verdict] ?? r.verdict : '';
  return <Panel title="Check a link" sub="· adds it to the feed">
    <form className="qc" onSubmit={e => { e.preventDefault(); run(); }}>
      <div className={`input-shell ${busy ? 'scanning' : ''}`}><span aria-hidden="true">⌕</span><label className="sr-only" htmlFor="qc">Link to check</label><input id="qc" value={v} onChange={e => setV(e.target.value)} placeholder="salik-fines.xyz/pay" autoComplete="off" spellCheck={false} /></div>
      <button className="button primary small" disabled={busy || !v.trim()}>{busy ? 'Checking…' : 'Check'}</button>
    </form>
    <p className="small muted">Shield never opens the link. It judges it from the outside.</p>
    {err && <p className="error">{err}</p>}
    {r && <div className={`qc-result ${tone(r.verdict)}`}>
      <strong>{title}</strong>
      {r.brand && r.verdict !== 'official' && <p>Looks like: {r.brand}</p>}
      <List title="FACTS" items={strip(r.facts)} /><List title="RULES" items={strip(r.rules)} />
      <List title="LEARNED WARNING SIGNS" items={(r.signals ?? []).filter(x => x.effect > 0.3).map(x => x.text)} /><List title="OTHER OBSERVATIONS" items={r.notes} />
      {r.advice && <p className="advice">{r.advice}</p>}
      {r.thresholds && <p className="small muted">Suspicious from {Math.round(r.thresholds.suspicious * 100)}, high risk from {Math.round(r.thresholds.high * 100)}{r.live_probability !== undefined ? ` · chance at a realistic 1% phishing rate: ${(r.live_probability * 100).toFixed(1)}%` : ''}.</p>}
    </div>}
  </Panel>;
}

/* ---------- radar stream, model, alerts ---------- */
function Stream({ radar }: { radar: Radar | null }) {
  return <Panel title="Certificate stream" sub={radar?.logs.length ? `· ${radar.logs.length} CT logs` : undefined}>
    <div className="terminal mono" aria-live="off">{radar?.recent.length ? radar.recent.slice(0, 12).map((x, i) => <div key={`${x}-${i}`}>{x}</div>) : <div className="muted">Start the radar to watch new certificates arrive.</div>}</div>
    {!!radar?.errors.length && <p className="small error">Last error: {radar.errors[0]}</p>}
  </Panel>;
}
function ModelPanel({ m, onRetrain }: { m: ModelStatus | null; onRetrain: () => void }) {
  const info = m?.model, x = info?.results ?? {}, s = x.at_suspicious ?? {}, h = x.at_high ?? {}, u = x.uae_fakes ?? {}, ns = x.never_seen?.unseen_frozen, nu = x.never_seen?.uae_frozen?.all;
  return <Panel title="Model" sub={info?.trained_at ? `· trained ${info.trained_at}` : undefined}>
    {!m ? <div className="skeleton sk-block" /> : !info ? <p className="muted">Not trained. Run <code>python ml/train_baseline.py</code>.</p> : <>
      <div className="metric-tiles">
        <div><span className="mono muted">AUC</span><strong>{x.auc ?? '—'}</strong></div>
        <div><span className="mono muted">Precision</span><strong>{pct(s.precision)}</strong></div>
        <div><span className="mono muted">Recall</span><strong>{pct(s.recall)}</strong></div>
        <div><span className="mono muted">False alarms</span><strong>{pct(s.false_positive_rate)}</strong></div>
      </div>
      <KV rows={[
        ['High risk: precision / recall', `${pct(h.precision)} / ${pct(h.recall)}`],
        ['Never-seen domains caught', ns?.phishing ? `${pct(ns.phishing.app_suspicious_or_higher)} · false alarms ${pct(ns.legit?.app_suspicious_or_higher)}` : '—'],
        ['Never-seen UAE scams caught', nu ? `${pct(nu.app_suspicious_or_higher)} of ${nu.n}` : '—'],
        ['Real UAE fakes (dev set)', u.total ? `${(u['high risk'] ?? 0) + (u.suspicious ?? 0)} of ${u.total} caught` : '—'],
        ['Free-hosting false alarms', pct(x.real_legit_hostnames?.free_host_suspicious_or_higher)],
        ['Training rows', (info.train_rows ?? 0).toLocaleString()], ['Combiner', info.combiner]]} />
      <button className="button secondary small wide" onClick={onRetrain} disabled={m.running}>{m.running ? 'Retraining… (5–10 min)' : 'Retrain on fresh feeds + analyst labels'}</button>
      {!!m.log.length && <pre className="terminal mono small">{m.log.join('\n')}</pre>}
    </>}
  </Panel>;
}
function Alerts({ a }: { a: Alert[] | null }) {
  return <Panel title="Alerts" sub="· demo inbox only">
    {!a ? <div className="skeleton sk-line wide" /> : !a.length ? <p className="muted">No alerts yet.</p> :
      <ul className="alert-list">{a.slice(0, 8).map(x => <li key={x.id}><span className={`status ${x.status === 'failed' ? 'confirmed' : ''}`}>{x.status === 'sent' ? 'Sent' : x.status === 'saved' ? 'Saved' : 'Failed'}</span><span className="mono dom">{x.domain}</span><span className="small muted">{x.created_at} UTC · {x.detail}</span></li>)}</ul>}
  </Panel>;
}

/* ---------- app ---------- */
export default function AdminApp() {
  const { toasts, push } = useToasts();
  const [source, setSource] = useState('');
  const [selected, setSelected] = useState<Detection | null>(null);
  const [ask, setAsk] = useState<Ask | null>(null);
  const [replayBusy, setReplayBusy] = useState(false);
  const feedPath = `/feed?limit=150${source === 'watch' ? '&source=live&flagged_only=false' : source ? `&source=${source}` : ''}`;
  const [stats, loadStats] = usePoll<Stats>('/stats', 2000);
  const [radar, loadRadar] = usePoll<Radar>('/radar', 2000);
  const [feed, loadFeed] = usePoll<Detection[]>(feedPath, 4000, [feedPath]);
  const [alerts, loadAlerts] = usePoll<Alert[]>('/alerts', 6000);
  const [model, loadModel] = usePoll<ModelStatus>('/model', 3000);
  const refresh = () => { loadStats(); loadFeed(); loadAlerts(); };
  const confirm = (title: string, body: string, ok: string) => new Promise<boolean>(resolve => setAsk({ title, body, ok, resolve }));

  const toggleRadar = async () => {
    try { await post(radar?.running ? '/radar/stop' : '/radar/start'); push(radar?.running ? 'Radar stopping…' : 'Connecting to Certificate Transparency logs…'); }
    catch (e) { push(`Radar error: ${(e as Error).message}`, true); }
    setTimeout(loadRadar, 800);
  };
  const replay = async () => { setReplayBusy(true); try { const r = await post<{ loaded: number }>('/replay/load'); push(`Loaded ${r.loaded} real UAE-targeted phishing domains`); refresh(); } catch (e) { push((e as Error).message, true); } setReplayBusy(false); };
  const label = async (d: Detection, yes: boolean) => {
    try { await post(`/detections/${d.id}/label`, { is_phishing: yes }); push(yes ? `${d.domain} confirmed as phishing · used in the next retrain` : `${d.domain} marked legit · used in the next retrain`); refresh(); }
    catch (e) { push((e as Error).message, true); }
  };
  const alert = async (d: Detection) => {
    if (!(await confirm(`Send an alert for ${d.domain}?`, 'Demo mode: the e-mail goes to your team inbox (ALERT_TO in .env), not to a real government address.', 'Send alert'))) return;
    try { const r = await post<{ detail?: string }>(`/detections/${d.id}/alert`); push(r.detail ?? 'Alert sent'); } catch (e) { push(`Alert error: ${(e as Error).message}`, true); }
    refresh();
  };
  const retrain = async () => { try { await post('/model/retrain'); push('Retraining started: downloading fresh phishing feeds…'); } catch (e) { push((e as Error).message, true); } loadModel(); };

  return <>
    <a className="skip-link" href="#console">Skip to content</a>
    <Header radar={radar} onRadar={toggleRadar} onReplay={replay} busy={replayBusy} />
    <main id="console" className="admin-wrap admin">
      <OpsBand stats={stats} radar={radar} feed={feed && source === '' ? feed : null} />
      <Kpis stats={stats} />
      <div className="admin-grid">
        <Detections rows={feed} source={source} setSource={s => { setSource(s); }} selected={selected?.id ?? null} onSelect={setSelected} onLabel={label} onAlert={alert} />
        <aside className="side">
          <AnimatePresence initial={false}>{selected && <motion.div key={selected.id} initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} transition={{ duration: .25 }}>
            <InvestigationPanel d={selected} onClose={() => setSelected(null)} onLabel={label} onAlert={alert} toast={push} />
          </motion.div>}</AnimatePresence>
          <QuickCheck onDone={refresh} />
          <Stream radar={radar} />
          <ModelPanel m={model} onRetrain={retrain} />
          <Alerts a={alerts} />
        </aside>
      </div>
    </main>
    <ConfirmDialog ask={ask} close={v => { ask?.resolve(v); setAsk(null); }} />
    <div className="toasts" aria-live="polite">{toasts.map(t => <div key={t.id} className={`toast glass ${t.bad ? 'bad' : ''}`}>{t.text}</div>)}</div>
  </>;
}
