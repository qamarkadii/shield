import { useMemo, useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Line, OrbitControls } from '@react-three/drei';
import { Bloom, EffectComposer } from '@react-three/postprocessing';
import * as THREE from 'three';
import { colors } from '../lib/model';
const CONFIG={radius:2.8,desktopDots:2400,mobileDots:900,arcCount:9,travelSeconds:4,rotationSpeed:.035};
function Signal({index}:{index:number}){
 const particle=useRef<THREE.Mesh>(null);const ring=useRef<THREE.Mesh>(null);const trail=useRef<THREE.Group>(null);
 // Quadratic Bezier paths start on the hemisphere and bend above its surface into the core.
 // Change arcCount, radius, or the control-point lift to tune density and curvature.
 const curve=useMemo(()=>{const angle=index*2.399;const start=new THREE.Vector3(Math.cos(angle)*2.7,Math.sin(angle)*1.65,.5);return new THREE.QuadraticBezierCurve3(start,start.clone().multiplyScalar(.6).add(new THREE.Vector3(0,.7,1.8)),new THREE.Vector3(0,0,1.15));},[index]);
 const points=useMemo(()=>curve.getPoints(60),[curve]);
 const samples=useMemo(()=>Array.from({length:7},()=>new THREE.Vector3()),[]);
 useFrame(({clock})=>{
  const phase=(clock.elapsedTime/CONFIG.travelSeconds+index/CONFIG.arcCount)%1;const intercepted=phase>.78;const color=intercepted?colors.cyan:colors.red;
  // The head and progressively dimmer particles sample the same curve: no per-frame geometry allocations.
  if(particle.current){curve.getPoint(Math.min(phase/.78,1),samples[0]);particle.current.position.copy(samples[0]);(particle.current.material as THREE.MeshBasicMaterial).color.set(color);particle.current.visible=!intercepted;}
  trail.current?.children.forEach((child,j)=>{curve.getPoint(Math.max(0,Math.min((phase-j*.014)/.78,1)),samples[j]);child.position.copy(samples[j]);( (child as THREE.Mesh).material as THREE.MeshBasicMaterial).color.set(color);});
  // Arrival changes the entire arc to protection cyan and emits a short expanding shockwave.
  if(ring.current){const p=(phase-.78)/.22;ring.current.visible=intercepted;ring.current.scale.setScalar(.1+Math.max(0,p)*1.7);(ring.current.material as THREE.MeshBasicMaterial).opacity=intercepted?(1-p)*.6:0;}
  const line=trail.current?.parent?.getObjectByName(`arc-${index}`) as THREE.Line|undefined;if(line){const m=line.material as THREE.LineBasicMaterial;m.color?.set(color);}
 });
 return <group><Line name={`arc-${index}`} points={points} color={colors.red} transparent opacity={.35} lineWidth={1}/><mesh ref={particle}><sphereGeometry args={[.035,8,8]}/><meshBasicMaterial color={colors.red} toneMapped={false}/></mesh><group ref={trail}>{samples.map((_,i)=><mesh key={i}><sphereGeometry args={[.025-i*.002,6,6]}/><meshBasicMaterial color={colors.red} transparent opacity={1-i*.12} toneMapped={false}/></mesh>)}</group><mesh ref={ring} position={[0,0,1.2]}><ringGeometry args={[.95,1,64]}/><meshBasicMaterial color={colors.cyan} transparent opacity={0} side={THREE.DoubleSide} toneMapped={false}/></mesh></group>
}
function Globe(){const globe=useRef<THREE.Group>(null);const mobile=window.innerWidth<640;
 const dots=useMemo(()=>{const count=mobile?CONFIG.mobileDots:CONFIG.desktopDots;const array=new Float32Array(count*3);for(let i=0;i<count;i++){const y=1-(i/count)*2;const r=Math.sqrt(1-y*y);const theta=i*2.399963;array[i*3]=Math.cos(theta)*r*CONFIG.radius;array[i*3+1]=y*CONFIG.radius*.66;array[i*3+2]=Math.abs(Math.sin(theta)*r*CONFIG.radius)*.65-.7;}return array;},[mobile]);
 useFrame(({clock,pointer},delta)=>{if(globe.current){globe.current.rotation.y=clock.elapsedTime*CONFIG.rotationSpeed;globe.current.rotation.x=THREE.MathUtils.lerp(globe.current.rotation.x,pointer.y*.07,delta*2);}});
 return <group><group ref={globe}><points><bufferGeometry><bufferAttribute attach="attributes-position" args={[dots,3]}/></bufferGeometry><pointsMaterial color={colors.cyan} size={.018} transparent opacity={.65} sizeAttenuation/></points>{[0,1,2,3,4].map(i=><Line key={i} points={Array.from({length:129},(_,j)=>{const a=j/128*Math.PI*2;return [Math.cos(a)*2.8,Math.sin(a)*1.85*Math.cos(i*.5),Math.sin(a)*1.85*Math.sin(i*.5)-.4] as [number,number,number]})} color={colors.cyan} transparent opacity={.12} lineWidth={1}/>)}</group>{Array.from({length:mobile?5:CONFIG.arcCount},(_,i)=><Signal key={i} index={i}/>)}<mesh rotation={[0,0,0]} position={[0,0,.8]}><ringGeometry args={[.88,.89,96]}/><meshBasicMaterial color={colors.cyan} transparent opacity={.4}/></mesh></group>
}
function Pipeline({stage}:{stage:number}){const root=useRef<THREE.Group>(null);useFrame(({clock})=>{if(root.current)root.current.rotation.y=Math.sin(clock.elapsedTime*.3)*.08});return <group ref={root}>{[0,1,2,3].map(i=><group key={i} position={[(i-1.5)*1.7,0,0]}><mesh rotation={[.4,.6,.2]}><icosahedronGeometry args={[.45,i===2?1:0]}/><meshBasicMaterial color={colors.cyan} wireframe transparent opacity={i===stage?1:.2}/></mesh>{i<3&&<Line points={[[.5,0,0],[1.2,0,0]]} color={colors.cyan} transparent opacity={i<stage?.8:.15}/>}</group>)}</group>}
export default function Scene({active,pipeline,stage}:{active:boolean;pipeline:boolean;stage:number}){const mobile=window.innerWidth<640;return <Canvas dpr={[1,2]} frameloop={active?'always':'never'} camera={{position:[0,0,7],fov:45}} gl={{alpha:true,antialias:!mobile,powerPreference:'high-performance'}}><ambientLight intensity={.5}/>{pipeline?<Pipeline stage={stage}/>:<Globe/>}{!pipeline&&<OrbitControls enableZoom={false} enablePan={false} rotateSpeed={.35} minPolarAngle={Math.PI*.35} maxPolarAngle={Math.PI*.65}/>} {!mobile&&<EffectComposer multisampling={0}><Bloom luminanceThreshold={.4} intensity={.6} mipmapBlur/></EffectComposer>}</Canvas>}
