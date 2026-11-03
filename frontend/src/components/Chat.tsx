import { Fragment, useEffect, useRef, useState, type FormEvent, type KeyboardEvent, type ReactNode } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { chatStream, chatUrl, type Analysis, type ChatTurn } from '../lib/model';
import './chat.css';

interface Message {id:number;role:'user'|'assistant';content:string;checks:Analysis[];error?:string;pending?:boolean}

const SUGGESTIONS=[
 'I got an SMS: "Unpaid Salik fine, pay now at salik-pay.com". Is it real?',
 'How do I report a scam message in the UAE?',
 'Check emirates-post.org',
 'وصلتني رسالة من رقم غريب فيها رابط، كيف أعرف إذا كانت احتيال؟',
];
const danger=(v:string)=>v==='high risk'||v==='suspicious';
const tone=(v:string)=>danger(v)?'danger':v==='official'?'safe':'';

/** Tiny, safe Markdown subset (bold, inline code, bullet / numbered lists, paragraphs). No HTML is ever injected. */
function inline(text:string):ReactNode[]{
 return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean).map((part,i)=>
  part.startsWith('**')&&part.endsWith('**')?<strong key={i}>{part.slice(2,-2)}</strong>:
  part.startsWith('`')&&part.endsWith('`')?<code key={i}>{part.slice(1,-1)}</code>:<Fragment key={i}>{part}</Fragment>);
}
function Markdown({text}:{text:string}){
 const blocks:ReactNode[]=[];let list:{ordered:boolean;items:string[]}|null=null;let para:string[]=[];
 const flushPara=()=>{if(para.length){blocks.push(<p key={blocks.length}>{inline(para.join(' '))}</p>);para=[]}};
 const flushList=()=>{if(list){const items=list.items.map((t,i)=><li key={i}>{inline(t)}</li>);blocks.push(list.ordered?<ol key={blocks.length}>{items}</ol>:<ul key={blocks.length}>{items}</ul>);list=null}};
 for(const raw of text.split('\n')){
  const line=raw.trim();const bullet=line.match(/^[-*•]\s+(.*)$/);const numbered=line.match(/^\d+[.)]\s+(.*)$/);
  if(!line){flushPara();flushList();continue}
  if(/^#{1,6}\s+/.test(line)){flushPara();flushList();blocks.push(<p key={blocks.length} className="md-heading">{inline(line.replace(/^#+\s+/,''))}</p>);continue}
  if(bullet||numbered){flushPara();const ordered=!!numbered;if(!list||list.ordered!==ordered){flushList();list={ordered,items:[]}}list.items.push((bullet??numbered)![1]);continue}
  flushList();para.push(line);
 }
 flushPara();flushList();
 return <>{blocks}</>;
}

function Gauge({result}:{result:Analysis}){
 const d=danger(result.verdict);
 return <div className={`gauge ${d?'danger':''}`}><svg viewBox="0 0 160 160" aria-hidden="true"><circle className="gauge-track" cx="80" cy="80" r="68"/><motion.circle key={result.domain} cx="80" cy="80" r="68" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeDasharray="427.26" initial={{strokeDashoffset:427.26}} animate={{strokeDashoffset:427.26*(1-(result.score??0)/100)}} transition={{duration:1}}/></svg><div><strong>{result.score??'—'}</strong><span className="mono">RISK SCORE / 100</span></div></div>;
}

function Analysis_({result}:{result:Analysis}){
 return <motion.div key={result.domain} className="analysis" initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} transition={{duration:.3}}>
  <div className="result-title"><span className="mono">SHIELD MODEL RESULT</span><span className={`badge ${tone(result.verdict)}`}>{result.verdict}</span></div>
  <Gauge result={result}/>
  <p className="result-domain">{result.domain}</p>
  {result.brand&&result.verdict!=='official'&&<p className="analysis-brand"><span className="mono">IMITATES</span> {result.brand}{result.officialSites?.length?<> · real site: <b>{result.officialSites.join(', ')}</b></>:null}</p>}
  <p className="mono analysis-label">WARNING SIGNS SHIELD FOUND</p>
  <ul className="reasons">{result.reasons.map((r,i)=><li key={i}>{r}</li>)}</ul>
  {result.advice&&<p className="analysis-advice">{result.advice}</p>}
  <p className="small">The score ranks risk for review; it is not a fraud probability. “No warning signs” does not prove safety.</p>
 </motion.div>;
}

export default function Chat(){
 const [messages,setMessages]=useState<Message[]>([]);
 const [input,setInput]=useState('');
 const [busy,setBusy]=useState(false);
 const [selected,setSelected]=useState<Analysis|null>(null);
 const log=useRef<HTMLDivElement>(null);const field=useRef<HTMLTextAreaElement>(null);const abort=useRef<AbortController|null>(null);const result=useRef<HTMLDivElement>(null);const nextId=useRef(1);

 useEffect(()=>{const el=log.current;if(el)el.scrollTop=el.scrollHeight},[messages]);
 useEffect(()=>()=>abort.current?.abort(),[]);

 async function send(text:string){
  const content=text.trim();if(!content||busy)return;
  const user:Message={id:nextId.current++,role:'user',content,checks:[]};
  const bot:Message={id:nextId.current++,role:'assistant',content:'',checks:[],pending:true};
  const history:ChatTurn[]=[...messages.filter(m=>m.content&&!m.error).map(m=>({role:m.role,content:m.content})),{role:'user',content}];
  setMessages(m=>[...m,user,bot]);setInput('');setBusy(true);
  const update=(fn:(m:Message)=>Message)=>setMessages(all=>all.map(m=>m.id===bot.id?fn(m):m));
  const controller=new AbortController();abort.current=controller;
  try{
   await chatStream(history,e=>{
    if(e.type==='check'){update(m=>({...m,checks:[...m.checks,e.data]}));setSelected(e.data)}
    else if(e.type==='delta')update(m=>({...m,content:m.content+e.text}));
    else if(e.type==='error')update(m=>({...m,error:e.message}));
   },controller.signal);
  }catch(err){
   if(!(err instanceof DOMException&&err.name==='AbortError'))update(m=>({...m,error:err instanceof Error?err.message:'The assistant is unavailable. Please retry.'}));
  }finally{update(m=>({...m,pending:false}));setBusy(false);abort.current=null;field.current?.focus()}
 }
 const submit=(e:FormEvent)=>{e.preventDefault();send(input)};
 const onKey=(e:KeyboardEvent<HTMLTextAreaElement>)=>{if(e.key==='Enter'&&!e.shiftKey&&!e.nativeEvent.isComposing){e.preventDefault();send(input)}};
 const reset=()=>{abort.current?.abort();setMessages([]);setSelected(null);setInput('')};

 return <section id="demo" className="section wrap">
  <div className="section-heading reveal"><div><p className="eyebrow">ASK SHIELD</p><h2>Paste a link.<br/><span>Or just ask.</span></h2></div><p>Shield checks any link you paste and answers your questions about scams, in Arabic or English.</p></div>
  <div className="demo-grid chat-grid glass">
   <div className="chat-panel">
    <div className="panel-header"><span className="mono">SHIELD ASSISTANT</span><span className="chat-header-actions">{messages.length>0&&<button type="button" className="text-button" onClick={reset}>New chat</button>}<span className="badge">{chatUrl?'AI ASSISTANT':'OFFLINE'}</span></span></div>
    <div className="chat-log" ref={log} aria-live="polite" aria-busy={busy}>
     {messages.length===0?<div className="chat-empty">
      <div className="idle-reticle"><span>⌕</span></div>
      <h3>Is that link real?</h3>
      <p>Paste a link from an SMS, WhatsApp or email, or ask about a message you received. Shield never opens the links you share.</p>
      <div className="examples">{SUGGESTIONS.map(s=><button type="button" key={s} dir="auto" onClick={()=>send(s)} disabled={busy||!chatUrl}>{s} ↗</button>)}</div>
     </div>:<AnimatePresence initial={false}>{messages.map(m=><motion.div key={m.id} className={`bubble ${m.role}`} initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} transition={{duration:.2}}>
      <span className="mono bubble-who">{m.role==='user'?'YOU':'SHIELD'}</span>
      {m.checks.length>0&&<div className="check-chips">{m.checks.map(c=><button type="button" key={c.domain} className={`check-chip ${tone(c.verdict)} ${selected===c?'active':''}`} onClick={()=>{setSelected(c);if(matchMedia('(max-width:760px)').matches)result.current?.scrollIntoView({behavior:'smooth',block:'start'})}} aria-pressed={selected===c}><i className="status-dot"/>{c.domain}<b>{c.verdict}{c.score!==null?` · ${c.score}`:''}</b></button>)}</div>}
      <div className="bubble-body" dir="auto">{m.role==='assistant'?<Markdown text={m.content}/>:<p>{m.content}</p>}{m.pending&&!m.content&&<span className="typing" aria-label="Shield is typing"><i/><i/><i/></span>}</div>
      {m.error&&<p className="error" role="alert">{m.error}</p>}
     </motion.div>)}</AnimatePresence>}
    </div>
    <form className="chat-composer" onSubmit={submit}>
     <div className={`input-shell ${busy?'scanning':''}`}>
      <label htmlFor="chat-input" className="sr-only">Message Shield</label>
      <textarea id="chat-input" ref={field} rows={1} dir="auto" value={input} onChange={e=>setInput(e.target.value)} onKeyDown={onKey} placeholder={chatUrl?'Paste a link or ask a question…':'Start Shield to chat with the assistant'} maxLength={2000} disabled={!chatUrl} autoComplete="off" spellCheck/>
      {busy?<button type="button" className="send" onClick={()=>abort.current?.abort()} aria-label="Stop">■</button>:<button type="submit" className="send" disabled={!input.trim()||!chatUrl} aria-label="Send">↗</button>}
     </div>
     <p className="small">Link verdicts come from Shield's model. Answers are written by DeepSeek AI, which receives your messages and can make mistakes. Never share passwords, OTP codes or card numbers.</p>
    </form>
   </div>
   <div className="demo-result chat-result" aria-live="polite" ref={result}>
    {selected?<Analysis_ result={selected}/>:<><div className="idle-reticle"><span>◎</span></div><h3>Link analysis</h3><p>When you share a link, Shield's verdict, score and warning signs appear here.</p><span className="mono muted">AWAITING A LINK_</span></>}
   </div>
  </div>
 </section>;
}
