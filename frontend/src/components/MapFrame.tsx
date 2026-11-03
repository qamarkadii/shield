import { Component, lazy, Suspense, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useInView, useReducedMotion } from 'framer-motion';
import { LAND } from '../lib/landDots';
const ThreatMap = lazy(() => import('./ThreatMap'));

/** Flat SVG version of the map: shown on low-power devices, with reduced motion, or while the 3D map loads. */
export function StaticMap() {
  const dots = useMemo(() => {
    const out: string[] = [];
    for (let i = 0; i < LAND.length; i += 2) {
      const x = LAND[i], y = LAND[i + 1];
      if (Math.abs(x) > 100 || y > 50 || y < -45) continue;
      out.push(`M${(400 + x * 4).toFixed(1)} ${(230 - y * 4).toFixed(1)}h.01`);
    }
    return out.join('');
  }, []);
  const arrows = [[-82, 28], [-60, -18], [-30, 26], [64, 8], [48, -30], [86, 30], [-12, -34]];
  return <div className="static-map" aria-hidden="true"><svg viewBox="0 0 800 460">
    <defs><radialGradient id="mapHalo"><stop stopColor="#00E5FF" stopOpacity=".16" /><stop offset="1" stopColor="#00E5FF" stopOpacity="0" /></radialGradient>
      <marker id="head" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0 0L10 5L0 10z" fill="#FF2E4D" /></marker></defs>
    <path d={dots} stroke="#00E5FF" strokeOpacity=".35" strokeWidth="3" strokeLinecap="round" />
    <circle cx="400" cy="230" r="120" fill="url(#mapHalo)" />
    <circle cx="400" cy="230" r="34" fill="none" stroke="#00E5FF" strokeWidth="1.5" />
    {arrows.map(([x, y], i) => { const sx = 400 + x * 4, sy = 230 - y * 4, a = Math.atan2(sy - 230, sx - 400), ex = 400 + Math.cos(a) * 38, ey = 230 + Math.sin(a) * 38, mx = (sx + ex) / 2, my = (sy + ey) / 2 - 60;
      return <path key={i} d={`M${sx} ${sy}Q${mx} ${my} ${ex} ${ey}`} fill="none" stroke="#FF2E4D" strokeOpacity=".75" strokeWidth="1.5" markerEnd="url(#head)" />; })}
  </svg></div>;
}

class Boundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() { return this.state.failed ? <StaticMap /> : this.props.children; }
}

export default function MapFrame({ compact = false, arrows, speed, paused = false, onIntercept, label }: { compact?: boolean; arrows?: number; speed?: number; paused?: boolean; onIntercept?: () => void; label: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const visible = useInView(ref, { margin: '100px' });
  const reduced = useReducedMotion();
  const [capable, setCapable] = useState(false);
  const [tabVisible, setTabVisible] = useState(true);
  useEffect(() => {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2');
    setCapable(!!gl && (navigator.hardwareConcurrency || 8) >= 4);
    gl?.getExtension('WEBGL_lose_context')?.loseContext();
    const update = () => setTabVisible(!document.hidden);
    document.addEventListener('visibilitychange', update);
    return () => document.removeEventListener('visibilitychange', update);
  }, []);
  return <div ref={ref} className={`map-frame ${compact ? 'compact' : ''}`} role="img" aria-label={label}>
    {capable && !reduced
      ? <Boundary><Suspense fallback={<div className="map-skeleton skeleton"><StaticMap /></div>}>
          <ThreatMap active={visible && tabVisible && !paused} compact={compact} arrows={arrows} speed={speed} onIntercept={onIntercept} />
        </Suspense></Boundary>
      : <StaticMap />}
  </div>;
}
