import { useEffect, useState } from 'react';
import { apiBase } from '../lib/model';

type Point={precision:number;recall:number;f1:number;false_positive_rate:number;'precision_at_1%_phishing':number;confusion:{tp:number;fp:number;tn:number;fn:number}};
type Evidence={available:boolean;model_sha256?:string;trained_at?:string;train_rows?:number;results?:{auc:number;at_suspicious:Point;at_high:Point}};
const pct=(n:number)=>`${(100*n).toFixed(1)}%`;

export default function Performance(){
 const [threshold,setThreshold]=useState<'suspicious'|'high'>('suspicious');
 const [data,setData]=useState<Evidence|null>(null);const [error,setError]=useState(false);
 useEffect(()=>{const control=new AbortController();fetch(`${apiBase}/api/model-status`,{signal:control.signal}).then(r=>{if(!r.ok)throw new Error('status unavailable');return r.json()}).then(setData).catch(e=>{if(e.name!=='AbortError')setError(true)});return()=>control.abort()},[]);
 const p=data?.results?.[threshold==='high'?'at_high':'at_suspicious'];
 return <section id="performance" className="section wrap">
  <div className="section-heading"><div><p className="eyebrow">ACCURACY</p><h2>How often<br/><span>is Shield right?</span></h2></div><p>Measured on 10,000 test sites, half of them real scams. Shield can still miss a scam or flag a genuine site, so always use the official app or website.</p></div>
  {error||data?.available===false||(data&&!p)?<div className="glass evidence-panel"><h3>Results unavailable</h3><p>The model's test results could not be loaded right now.</p></div>:!data?<p role="status">Loading results…</p>:<>
   <div className="segmented" aria-label="Warning level">{(['suspicious','high'] as const).map(t=><button key={t} aria-pressed={threshold===t} onClick={()=>setThreshold(t)}>{t==='high'?'High risk':'Suspicious or higher'}</button>)}</div>
   <div className="metric-grid glass">{[['SCAMS CAUGHT',pct(p!.recall),'of the scam sites in the test'],['WARNINGS THAT WERE REAL SCAMS',pct(p!.precision),'of the sites Shield warned about'],['GENUINE SITES WRONGLY FLAGGED',pct(p!.false_positive_rate),'false alarms'],['OVERALL SCORE (AUC)',data?.results?.auc.toFixed(3),'1.000 would be perfect']].map(([label,value,note])=><div className="metric" key={label}><span className="mono">{label}</span><strong>{value}</strong><span className="small">{note}</span></div>)}</div>
   <p className="small">Shield judges the link's address, not the page itself. <a href="/model-card.md">Full model details ↗</a></p>
  </>}
 </section>
}
