export const colors = {bg:'#05060A',cyan:'#00E5FF',red:'#FF2E4D',text:'#EDEFF5'};
export const metrics = {auc:0.951, precision:95.4,recall:84.1,f1:89.4,training:276270,test:10000};
export type Verdict = 'high risk'|'suspicious'|'no warning signs'|'official'|'unknown';
export interface Analysis {domain:string;score:number|null;verdict:Verdict;reasons:string[];rule?:string|null;simulated:boolean;brand?:string|null;officialSites?:string[];advice?:string}
export function normalizeDomain(input:string){
 const raw=input.trim(); if(!raw)throw new Error('Enter a domain or URL to inspect.');
 let url:URL; try{url=new URL(raw.includes('://')?raw:`https://${raw}`)}catch{throw new Error('Enter a valid domain, such as example.com.');}
 if(!['http:','https:'].includes(url.protocol)||url.username||url.password||!url.hostname.includes('.')||url.hostname.length>253||!url.hostname.split('.').every(x=>/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(x)))throw new Error('Use a valid HTTP(S) URL or domain without credentials.');
 return url.hostname.toLowerCase().replace(/^www\./,'');
}
const env=(import.meta as unknown as {env:Record<string,string>}).env;
export const apiBase = (env.VITE_MODEL_API_BASE||'').replace(/\/$/,'');
// VITE_SHIELD_PUBLIC=1: the site is served by Shield's public app (home page) and calls its POST /api/check on the same origin.
export const shieldPublic = env.VITE_SHIELD_PUBLIC==='1';
export const apiConnected = shieldPublic||!!apiBase;
const VERDICTS=['high risk','suspicious','no warning signs','official','unknown'];
function validate(data:{verdict?:unknown;score?:unknown;reasons?:unknown}){if(!VERDICTS.includes(data.verdict as string)||!(data.score===null||(typeof data.score==='number'&&data.score>=0&&data.score<=100))||!Array.isArray(data.reasons)||!data.reasons.every((x:unknown)=>typeof x==='string'))throw new Error('The model returned an invalid response.');}
// Shield public result (POST /api/check, or a "check" event of /api/chat) -> what the site shows.
interface ShieldPublic {domain?:string;score?:number|null;verdict?:string;brand?:string|null;official_sites?:unknown;en?:{facts?:string[];rules?:string[];signals?:string[];notes?:string[];advice?:string}}
export function fromShield(d:ShieldPublic,fallbackDomain=''):Analysis{
 const en=d.en??{};
 const reasons:string[]=[...(en.rules??[]),...(en.facts??[]),...(en.signals??[]),...(en.notes??[])];
 const data={domain:d.domain??fallbackDomain,score:d.score??null,verdict:d.verdict as Verdict,reasons:reasons.length?reasons:['No warning signs found in the name. This does not prove the site is safe.']};
 validate(data);
 return {...data,simulated:false,brand:d.brand??null,officialSites:Array.isArray(d.official_sites)?d.official_sites.filter((x):x is string=>typeof x==='string'):[],advice:en.advice||''};
}
export type ChatRole='user'|'assistant';
export interface ChatTurn {role:ChatRole;content:string}
export type ChatEvent={type:'check';data:Analysis}|{type:'delta';text:string}|{type:'error';message:string}|{type:'done'};
// Chat assistant: Shield checks every link in the message with its own model, then the language model explains it.
export const chatUrl = shieldPublic?'/api/chat':apiBase?`${apiBase}/api/chat`:'';
export async function chatStream(messages:ChatTurn[],onEvent:(e:ChatEvent)=>void,signal?:AbortSignal){
 if(!chatUrl)throw new Error('The assistant needs the Shield service. Start Shield and open the site at /site/.');
 const response=await fetch(chatUrl,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({messages}),signal});
 if(response.status===429)throw new Error('Too many messages. Please wait a minute and try again.');
 if(!response.ok||!response.body)throw new Error('The assistant is unavailable. Please retry.');
 const reader=response.body.getReader();const decoder=new TextDecoder();let buffer='';
 const handle=(line:string)=>{
  if(!line.trim())return;let o:{type?:string;data?:ShieldPublic;text?:unknown;message?:unknown};try{o=JSON.parse(line)}catch{return}
  if(o.type==='check'&&o.data){try{onEvent({type:'check',data:fromShield(o.data)})}catch{/* skip a malformed result */}}
  else if(o.type==='delta'&&typeof o.text==='string')onEvent({type:'delta',text:o.text});
  else if(o.type==='error')onEvent({type:'error',message:String(o.message||'Something went wrong.')});
  else if(o.type==='done')onEvent({type:'done'});
 };
 for(;;){const {value,done}=await reader.read();if(done)break;buffer+=decoder.decode(value,{stream:true});let i:number;while((i=buffer.indexOf('\n'))>=0){handle(buffer.slice(0,i));buffer=buffer.slice(i+1)}}
 handle(buffer);
}
// REAL MODEL INTEGRATION: the sole request boundary. Shield public POST /api/check, or Shield GET /check?domain=.
// Never fetch a submitted domain. A configured API failure never falls back to mock results.
export async function analyzeDomain(input:string):Promise<Analysis>{
 const domain=normalizeDomain(input);
 if(shieldPublic){
  const response=await fetch('/api/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:domain}),signal:AbortSignal.timeout(12000)});
  if(response.status===429)throw new Error('Too many checks. Please wait a minute and try again.');
  if(!response.ok)throw new Error('The model service is unavailable. Please retry.');
  return fromShield(await response.json(),domain);
 }
 if(apiBase){const response=await fetch(`${apiBase}/check?domain=${encodeURIComponent(domain)}`,{signal:AbortSignal.timeout(12000)});if(!response.ok)throw new Error('The model service is unavailable. Please retry.');const data=await response.json();if(!['high risk','suspicious','no warning signs','official','unknown'].includes(data.verdict)||!(data.score===null||(typeof data.score==='number'&&data.score>=0&&data.score<=100))||!Array.isArray(data.reasons)||!data.reasons.every((x:unknown)=>typeof x==='string'))throw new Error('The model returned an invalid response.');return {...data,simulated:false};}
 await new Promise(resolve=>setTimeout(resolve,1400));
 // Deliberately illustrative heuristic, NOT the trained classifier or calibrated probability.
 const reasons:string[]=[];
 if(/login|verify|pay|parcel|refund/.test(domain))reasons.push('Illustrative signal: a lure word appears in the domain.');
 if(/\.(xyz|top|live|click|online|test)$/.test(domain))reasons.push('Illustrative signal: demo or frequently abused domain ending.');
 if(domain.split('.').length>3)reasons.push('Illustrative signal: multiple subdomain levels.');
 if(/salik|aramex|emirates|sa1ik/.test(domain))reasons.push('Illustrative signal: a watched brand pattern appears in the name.');
 const score=Math.min(99,12+reasons.length*22);
 return {domain,score,verdict:score>=84?'high risk':score>=58?'suspicious':'no warning signs',simulated:true,reasons:reasons.length?reasons:['No demo patterns matched. This does not establish that the site is safe.']};
}
