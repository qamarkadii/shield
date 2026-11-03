import { useEffect, useState } from 'react';
import { apiBase } from '../lib/model';

type Point={precision:number;recall:number;f1:number;false_positive_rate:number;'precision_at_1%_phishing':number;confusion:{tp:number;fp:number;tn:number;fn:number}};
type Slice={n:number;high:{flagged:number;rate:number;ci95:number[]};suspicious:{flagged:number;rate:number;ci95:number[]}};
type Evidence={available:boolean;model_sha256?:string;trained_at?:string;train_rows?:number;results?:{auc:number;at_suspicious:Point;at_high:Point};fresh_frozen?:Record<string,Slice>};
const pct=(n:number)=>`${(100*n).toFixed(1)}%`;

export default function Performance(){
 const [threshold,setThreshold]=useState<'suspicious'|'high'>('suspicious');
 const [data,setData]=useState<Evidence|null>(null);const [error,setError]=useState(false);
 useEffect(()=>{const control=new AbortController();fetch(`${apiBase}/api/model-status`,{signal:control.signal}).then(r=>{if(!r.ok)throw new Error('status unavailable');return r.json()}).then(setData).catch(e=>{if(e.name!=='AbortError')setError(true)});return()=>control.abort()},[]);
 const p=data?.results?.[threshold==='high'?'at_high':'at_suspicious'];
 return <section id="performance" className="section wrap">
  <div className="section-heading"><div><p className="eyebrow">04 / MEASURED EVIDENCE</p><h2>Useful warnings.<br/><span>Visible limitations.</span></h2></div><p>Research prototype. False alarms and missed scams remain. No live UAE prevention pilot has been demonstrated.</p></div>
  {error||data?.available===false?<div className="glass evidence-panel"><h3>Model evidence unavailable</h3><p>The service has not provided a loaded model and its results. Historical presentation numbers are not a substitute.</p></div>:!data?<p role="status">Loading evidence from the serving model…</p>:!p?<div className="glass evidence-panel"><h3>Model loaded; evaluation unavailable</h3><p>No evaluation report is attached to these weights. Accuracy claims are unavailable.</p></div>:<>
   <p className="small mono">MODEL {data?.model_sha256?.slice(0,12)} · TRAINED {data?.trained_at} · {data?.train_rows?.toLocaleString()} fitting rows</p>
   <div className="segmented" aria-label="Evaluation threshold">{(['suspicious','high'] as const).map(t=><button key={t} aria-pressed={threshold===t} onClick={()=>setThreshold(t)}>{t==='high'?'High risk':'Suspicious or higher'}</button>)}</div>
   <div className="metric-grid glass">{[['PRECISION ON BALANCED TEST',pct(p.precision)],['RECALL ON BALANCED TEST',pct(p.recall)],['FALSE ALARMS ON BALANCED TEST',pct(p.false_positive_rate)],['ROC AUC',data?.results?.auc.toFixed(3)]].map(([label,value])=><div className="metric" key={label}><span className="mono">{label}</span><strong>{value}</strong><span className="small">Fixed 10,000-domain test · 50% phishing</span></div>)}</div>
   <p className="small">Balanced-test precision is not deployment precision. Assuming 1% phishing and the same test recall/false-alarm rate gives {pct(p['precision_at_1%_phishing'])} precision. New-source results below can differ substantially.</p>
   <div className="evidence-grid"><div className="glass evidence-panel"><h3>Confusion matrix</h3><div className="matrix">{(['tp','fn','fp','tn'] as const).map((k,i)=><div key={k} className={i===1||i===2?'matrix-error':''}><span className="mono">{['TRUE POSITIVE','FALSE NEGATIVE','FALSE POSITIVE','TRUE NEGATIVE'][i]}</span><strong>{p.confusion[k].toLocaleString()}</strong></div>)}</div></div>
   <div className="glass evidence-panel"><h3>Fresh frozen source snapshot</h3>{data?.fresh_frozen?<><p>Collected 3 November 2026. Owners excluded from fitting/calibration. Ranking-based legitimate labels are unverified proxies.</p>{Object.entries(data.fresh_frozen).map(([name,s])=><p key={name}><strong>{name==='openphish_current'?'Phishing caught':name==='umbrella_hosting_proxy_legit'?'Hosting proxy false alarms':'Ranked-site proxy false alarms'}: {pct(s[threshold].rate)}</strong><br/><span className="small">{s[threshold].flagged}/{s.n} · 95% interval {pct(s[threshold].ci95[0])}–{pct(s[threshold].ci95[1])}</span></p>)}</>:<p>No independent snapshot is linked to these exact model bytes.</p>}</div></div>
   <p className="small">Scores rank domain warning signs; they do not prove a page is fraudulent or safe. The independent phishing sample is small. Free hosting remains a major weakness. <a href="/model-card.md">Read the model card ↗</a></p>
  </>}
 </section>
}
