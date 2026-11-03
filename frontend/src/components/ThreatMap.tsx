import { useMemo, useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Line } from '@react-three/drei';
import { Bloom, EffectComposer } from '@react-three/postprocessing';
import * as THREE from 'three';
import type { Line2 } from 'three-stdlib';
import { LAND } from '../lib/landDots';

/*
 Flat threat map. The world is a dotted plane centred on the UAE (AIDA Team = origin).
 Red 3D arrows (cone head + glowing trail) arc in from around the world and are stopped at the
 cyan ring around the centre, which pulses on every interception.

 Tuning: SCALE (units per degree), TILT (how far the map leans back), ARROW_* below.
*/
export const COLORS = { red: '#FF2E4D', cyan: '#00E5FF', ink: '#EDEFF5' };
const SCALE = 0.066;          // map units per degree
const TILT = -0.62;           // radians; map leans away from the viewer
const RING = 0.62;            // radius of the AIDA ring where arrows are intercepted
const TRAIL = 26;             // points in each arrow trail
const UP = new THREE.Vector3(0, 1, 0);

// Origins: land dots far enough from the UAE to give long, readable arcs.
const ORIGINS: [number, number][] = (() => {
  const out: [number, number][] = [];
  for (let i = 0; i < LAND.length; i += 2) {
    const x = LAND[i], y = LAND[i + 1], d = Math.hypot(x, y);
    if (d > 28 && d < 120 && y > -50 && y < 48) out.push([x * SCALE, y * SCALE]);
  }
  return out;
})();

function seeded(n: number) { const x = Math.sin(n * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); }

function Dots() {
  const geom = useMemo(() => {
    const n = LAND.length / 2, pos = new Float32Array(n * 3), col = new Float32Array(n * 3);
    const c = new THREE.Color(COLORS.cyan);
    for (let i = 0; i < n; i++) {
      const x = LAND[i * 2] * SCALE, y = LAND[i * 2 + 1] * SCALE;
      pos.set([x, y, 0], i * 3);
      const fall = Math.max(0.3, 1 - Math.hypot(x, y) / 8);   // brighter near the UAE
      col.set([c.r * fall, c.g * fall, c.b * fall], i * 3);
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    g.setAttribute('color', new THREE.BufferAttribute(col, 3));
    return g;
  }, []);
  return <points geometry={geom}><pointsMaterial size={0.034} vertexColors transparent opacity={0.85} sizeAttenuation depthWrite={false} /></points>;
}

function RangeRings() {
  const rings = [1.6, 3.2, 4.8];
  return <group>{rings.map((r, i) => <mesh key={r}><ringGeometry args={[r - 0.004, r + 0.004, 160]} /><meshBasicMaterial color={COLORS.cyan} transparent opacity={0.1 - i * 0.025} depthWrite={false} /></mesh>)}</group>;
}

interface ArrowState { curve: THREE.QuadraticBezierCurve3; start: number; dur: number; seed: number }

function Arrow({ index, count, onHit, speed }: { index: number; count: number; onHit: () => void; speed: number }) {
  const head = useRef<THREE.Mesh>(null);
  const trail = useRef<Line2>(null);
  const arc = useRef<Line2>(null);
  const tmp = useMemo(() => ({ p: new THREE.Vector3(), t: new THREE.Vector3(), buf: new Float32Array(TRAIL * 3), arcBuf: new Float32Array(48 * 3) }), []);
  const st = useRef<ArrowState | null>(null);

  const respawn = (now: number, k: number) => {
    const seed = index * 977 + k * 131;
    const [ox, oy] = ORIGINS[Math.floor(seeded(seed) * ORIGINS.length)] ?? [3, 2];
    const from = new THREE.Vector3(ox, oy, 0);
    const dir = from.clone().normalize();
    const to = dir.clone().multiplyScalar(RING).setZ(0.04);
    const dist = from.distanceTo(to);
    const mid = from.clone().add(to).multiplyScalar(0.5).setZ(0.28 + dist * 0.3);
    const curve = new THREE.QuadraticBezierCurve3(from, mid, to);
    st.current = { curve, start: now, dur: (2.6 + seeded(seed + 7) * 1.6) / speed, seed: k };
    for (let i = 0; i < 48; i++) { curve.getPoint(i / 47, tmp.p); tmp.arcBuf.set([tmp.p.x, tmp.p.y, tmp.p.z], i * 3); }
    arc.current?.geometry.setPositions(tmp.arcBuf);
  };

  useFrame(({ clock }) => {
    const now = clock.elapsedTime;
    if (!st.current) { respawn(now - (index / count) * 3.4, 0); }
    const s = st.current!;
    let p = (now - s.start) / s.dur;
    if (p >= 1) { onHit(); respawn(now, s.seed + 1); p = 0; }
    const ease = p < 0.5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2;
    s.curve.getPoint(ease, tmp.p);
    s.curve.getTangent(ease, tmp.t);
    if (head.current) {
      head.current.position.copy(tmp.p);
      head.current.quaternion.setFromUnitVectors(UP, tmp.t.normalize());
      head.current.scale.setScalar(0.6 + Math.min(1, p * 4) * 0.4);
    }
    // Trail: the last part of the path behind the head, sampled every frame (no allocations).
    for (let i = 0; i < TRAIL; i++) {
      const q = Math.max(0, ease - (i / (TRAIL - 1)) * 0.22);
      s.curve.getPoint(q, tmp.p);
      tmp.buf.set([tmp.p.x, tmp.p.y, tmp.p.z], i * 3);
    }
    trail.current?.geometry.setPositions(tmp.buf);
    const fade = p > 0.9 ? (1 - p) * 10 : Math.min(1, p * 6);
    if (arc.current) (arc.current.material as THREE.Material & { opacity: number }).opacity = 0.12 * fade;
    if (trail.current) (trail.current.material as THREE.Material & { opacity: number }).opacity = 0.9 * fade;
  });

  const init = useMemo(() => Array.from({ length: TRAIL }, () => [0, 0, 0] as [number, number, number]), []);
  const initArc = useMemo(() => Array.from({ length: 48 }, () => [0, 0, 0] as [number, number, number]), []);
  return <group>
    <Line ref={arc} points={initArc} color={COLORS.red} lineWidth={1} transparent opacity={0.12} depthWrite={false} />
    <Line ref={trail} points={init} color={COLORS.red} lineWidth={3} transparent opacity={0.9} depthWrite={false} />
    <mesh ref={head}><coneGeometry args={[0.085, 0.3, 16]} /><meshBasicMaterial color={COLORS.red} toneMapped={false} /></mesh>
  </group>;
}

function Core({ pulses }: { pulses: React.MutableRefObject<number[]> }) {
  const rings = useRef<THREE.Group>(null);
  const halo = useRef<THREE.Mesh>(null);
  useFrame(({ clock }) => {
    const now = clock.elapsedTime;
    rings.current?.children.forEach((child, i) => {
      const t0 = pulses.current[i] ?? -99;
      const k = (now - t0) / 1.1;
      const m = (child as THREE.Mesh).material as THREE.MeshBasicMaterial;
      child.visible = k >= 0 && k < 1;
      child.scale.setScalar(1 + k * 1.8);
      m.opacity = (1 - k) * 0.7;
    });
    if (halo.current) (halo.current.material as THREE.MeshBasicMaterial).opacity = 0.1 + Math.sin(now * 2.2) * 0.04;
  });
  return <group>
    <mesh ref={halo}><circleGeometry args={[RING * 1.25, 64]} /><meshBasicMaterial color={COLORS.cyan} transparent opacity={0.16} depthWrite={false} /></mesh>
    <mesh><ringGeometry args={[RING - 0.012, RING + 0.012, 96]} /><meshBasicMaterial color={COLORS.cyan} toneMapped={false} /></mesh>
    <mesh><ringGeometry args={[RING * 0.42, RING * 0.44, 64]} /><meshBasicMaterial color={COLORS.cyan} transparent opacity={0.5} /></mesh>
    <group ref={rings}>{[0, 1, 2, 3].map(i => <mesh key={i} visible={false}><ringGeometry args={[RING - 0.01, RING + 0.01, 96]} /><meshBasicMaterial color={COLORS.cyan} transparent opacity={0} toneMapped={false} depthWrite={false} /></mesh>)}</group>
  </group>;
}

function World({ arrows, speed, onIntercept }: { arrows: number; speed: number; onIntercept?: () => void }) {
  const root = useRef<THREE.Group>(null);
  const pulses = useRef<number[]>([]);
  const slot = useRef(0);
  const clock = useRef<THREE.Clock | null>(null);
  useFrame(({ clock: c, pointer }, delta) => {
    clock.current = c;
    if (root.current) {
      root.current.rotation.x = THREE.MathUtils.lerp(root.current.rotation.x, TILT + pointer.y * 0.05, delta * 2);
      root.current.rotation.z = THREE.MathUtils.lerp(root.current.rotation.z, -pointer.x * 0.06, delta * 2);
    }
  });
  const hit = () => {
    const now = clock.current?.elapsedTime ?? 0;
    pulses.current[slot.current % 4] = now; slot.current++;
    onIntercept?.();
  };
  return <group ref={root} rotation={[TILT, 0, 0]}>
    <Dots /><RangeRings /><Core pulses={pulses} />
    {Array.from({ length: arrows }, (_, i) => <Arrow key={i} index={i} count={arrows} onHit={hit} speed={speed} />)}
  </group>;
}

export default function ThreatMap({ active, arrows = 9, speed = 1, compact = false, onIntercept }: { active: boolean; arrows?: number; speed?: number; compact?: boolean; onIntercept?: () => void }) {
  const mobile = typeof window !== 'undefined' && window.innerWidth < 640;
  return <Canvas dpr={[1, 2]} frameloop={active ? 'always' : 'never'} camera={{ position: [0, compact ? -0.4 : -0.2, compact ? 7.2 : 8], fov: compact ? 34 : 38 }} gl={{ alpha: true, antialias: !mobile, powerPreference: 'high-performance' }}>
    <World arrows={mobile ? Math.min(arrows, 5) : arrows} speed={speed} onIntercept={onIntercept} />
    {!mobile && <EffectComposer multisampling={0}><Bloom luminanceThreshold={0.35} intensity={0.75} mipmapBlur /></EffectComposer>}
  </Canvas>;
}
