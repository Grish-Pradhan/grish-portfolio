import React, { useEffect, useRef, useState } from "react";
import "./technology-artifacts.css";

const studies = [
  { id: "network", title: "Connected network", topic: "Cybersecurity", description: "A web of connected nodes around a protected core. An exploration of trust, connections, and the systems between them." },
  { id: "processor", title: "Silicon architecture", topic: "Systems engineering", description: "A processor, its pins, and the circuit paths around it. A closer look at the structure beneath the software." },
  { id: "core", title: "Orbital data core", topic: "Software & automation", description: "A faceted core surrounded by three data orbits. A study of how information moves through a system." }
];

function StaticArtifact({ mode }) {
  return <svg viewBox="0 0 400 340" className="artifact-fallback" aria-hidden="true">
    <g fill="none" stroke="currentColor" strokeWidth="1.2">
      {mode === "processor" ? <g transform="translate(200 165) rotate(-25)"><rect x="-100" y="-100" width="200" height="200" rx="8" /><rect x="-42" y="-42" width="84" height="84" fill="#172c40" />{Array.from({ length: 7 }, (_, i) => <g key={i}><path d={`M ${i * 12 - 36} -42 v-40 M ${i * 12 - 36} 42 v40 M -42 ${i * 12 - 36} h-40 M 42 ${i * 12 - 36} h40`} /></g>)}</g> : <g><circle cx="200" cy="165" r="118" /><ellipse cx="200" cy="165" rx="118" ry="42" transform="rotate(-35 200 165)" /><ellipse cx="200" cy="165" rx="118" ry="42" transform="rotate(35 200 165)" /><path d="M200 110 248 165 200 220 152 165Z" fill="#163346" stroke="#f3bd78" />{mode === "network" && Array.from({ length: 16 }, (_, i) => { const a = i * Math.PI / 8; const x = 200 + Math.cos(a) * 118; const y = 165 + Math.sin(a) * 118; return <g key={i}><path d={`M200 165 ${x} ${y}`} opacity=".3" /><circle cx={x} cy={y} r="3" fill="currentColor" /></g>; })}</g>}
    </g>
  </svg>;
}

export default function TechnologyArtifacts() {
  const [mode, setMode] = useState("network");
  const [status, setStatus] = useState("loading");
  const [paused, setPaused] = useState(false);
  const mountRef = useRef(null);
  const sceneRef = useRef(null);
  const preferencesRef = useRef({ paused: false });
  const study = studies.find((item) => item.id === mode);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    import("./technology-scene.js").then(({ createTechnologyScene }) => {
      if (!active) return;
      try {
        sceneRef.current = createTechnologyScene(mountRef.current, mode, preferencesRef.current);
        setStatus("ready");
      } catch {
        setStatus("fallback");
      }
    }).catch(() => { if (active) setStatus("fallback"); });
    return () => { active = false; sceneRef.current?.dispose(); sceneRef.current = null; };
  }, [mode]);

  const toggleMotion = () => {
    preferencesRef.current.paused = !preferencesRef.current.paused;
    setPaused(preferencesRef.current.paused);
    sceneRef.current?.wake();
  };

  return <figure className="artifact-viewer">
    <div className="artifact-heading"><span>Technology studies</span><span className="artifact-topic">{study.topic}</span></div>
    <div className="artifact-stage">
      <div className="artifact-canvas" ref={mountRef} role="img" aria-label={`3D study: ${study.title}. ${study.description}`} />
      {status !== "ready" && <StaticArtifact mode={mode} />}
      <div className="artifact-coordinate" aria-hidden="true">{mode === "network" ? "64 nodes / one core" : mode === "processor" ? "32 pins / circuit paths" : "3 orbits / one core"}</div>
      <button className="artifact-motion" type="button" onClick={toggleMotion} aria-pressed={paused} disabled={status !== "ready"}>{paused ? "Resume motion" : "Pause motion"}</button>
    </div>
    <div className="artifact-options" role="group" aria-label="Choose a technology study">{studies.map((item) => <button type="button" key={item.id} aria-pressed={mode === item.id} onClick={() => setMode(item.id)}>{item.id === "network" ? "Network" : item.id === "processor" ? "Processor" : "Data core"}</button>)}</div>
    <figcaption className="artifact-caption" aria-live="polite"><h2>{study.title}</h2><p>{study.description}</p><span>{status === "fallback" ? "Static illustration shown on this device." : "Choose a study. Move your pointer to change the perspective."}</span></figcaption>
  </figure>;
}
