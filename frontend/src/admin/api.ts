// Analyst dashboard API. Paths are RELATIVE on purpose: the dashboard works at "/" on a laptop
// (http://127.0.0.1:8000) and under "/admin/" on the server (space_app.py).
export async function api<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const r = await fetch(path.replace(/^\//, ''), { headers: { 'Content-Type': 'application/json' }, ...opts });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((j as { detail?: string }).detail || r.statusText);
  return j as T;
}
export const post = <T,>(path: string, body?: unknown) => api<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });

export type Level = 'high risk' | 'suspicious' | 'no warning signs' | 'official' | 'unknown';
export interface Detection { id: number; domain: string; url: string | null; source: string; score: number | null; verdict: Level; brand: string | null; reasons: string[]; note: string | null; status: 'pending' | 'confirmed' | 'legit'; first_seen: string; last_seen: string; cert_issuer?: string | null; evidence?: string | null }
export interface Stats { certs_checked_now?: number; certs_per_second?: number; uae_seen_now?: number; radar_running?: boolean; flagged: number; high_risk: number; citizen_reports: number; alerts_sent: number; labels?: number; certs_checked_total?: number }
export interface Radar { running: boolean; logs: string[]; certs_checked: number; certs_per_second: number; uae_seen: number; recent: string[]; errors: string[] }
export interface Alert { id: number; domain: string; recipient: string; subject: string; status: string; detail: string; created_at: string }
interface Rates { precision?: number; recall?: number; false_positive_rate?: number; 'precision_at_1%_phishing'?: number }
interface NeverSeen { phishing?: { app_suspicious_or_higher?: number; n?: number }; legit?: { app_suspicious_or_higher?: number; n?: number }; auc?: number }
export interface ModelInfo {
  trained_at?: string; train_rows?: number; combiner?: string;
  results?: { auc?: number; at_suspicious?: Rates; at_high?: Rates; uae_fakes?: { 'high risk'?: number; suspicious?: number; 'no warning signs'?: number; total?: number; note?: string };
    real_legit_hostnames?: { n?: number; suspicious_or_higher?: number; free_host_suspicious_or_higher?: number };
    never_seen?: { unseen_frozen?: NeverSeen; uae_frozen?: { all?: { app_suspicious_or_higher?: number; n?: number } } } };
}
export interface ModelStatus { running: boolean; log: string[]; last: Record<string, unknown> | null; model: ModelInfo | null }
export interface Signal { text: string; effect: number }
export interface CheckResult { id?: number; domain: string; verdict: Level; score: number | null; brand?: string | null; facts?: string[]; rules?: string[]; signals?: Signal[]; notes?: string[]; advice?: string; thresholds?: { suspicious: number; high: number }; live_probability?: number }
export interface Investigation { domain: string; verdict: Level; name_verdict?: Level; score: number | null; reasons: string[];
  facts?: { rdap?: { age_days?: number | null; created?: string; registrar?: string; registrar_abuse_email?: string; not_applicable?: string };
    dns?: { resolves?: boolean; a?: string[]; mx?: string[] }; hosting?: { ip?: string; asn?: number; as_name?: string; country?: string; abuse?: { abuse_email?: string } };
    certificate?: { https?: boolean; issuer?: string; issued_days_ago?: number; names_covered?: number } } }
export interface PageCheck { verdict?: string; error?: string; title?: string; asks_for?: Record<string, boolean>; claims_brand_off_domain?: string[]; looks_like?: { brand: string; similarity: number }[]; final_url?: string; signs?: string[]; screenshot_url?: string }
export interface EvidencePack { domain: string; report_path: string; abuse_contacts?: { who: string; email: string }[]; evidence_sha256: string; page_verdict?: string }

export const LEVEL: Record<string, string> = { 'high risk': 'High risk', suspicious: 'Suspicious', official: 'Verified official', 'no warning signs': 'No warning signs', unknown: 'Unknown' };
export const tone = (v?: string) => v === 'high risk' ? 'high' : v === 'suspicious' ? 'mid' : v === 'official' ? 'ok' : 'low';
export const pct = (v?: number) => v === undefined || v === null ? '—' : `${(v * 100).toFixed(1)}%`;
