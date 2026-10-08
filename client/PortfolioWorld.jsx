import React, { useCallback, useEffect, useRef, useState } from "react";
import "./portfolio-world.css";

const places = [
  { id: "about", label: "About", name: "About pavilion", symbol: "01" },
  { id: "projects", label: "Projects", name: "Project workshop", symbol: "02" },
  { id: "certifications", label: "Certificates", name: "Credential gallery", symbol: "03" },
  { id: "achievements", label: "Milestones", name: "Milestone garden", symbol: "04" },
  { id: "contact", label: "Contact", name: "Contact beacon", symbol: "05" }
];
const url = value => {
  if (!value) return "#";
  try { const parsed = new URL(value, window.location.origin); return ["https:", "http:"].includes(parsed.protocol) ? parsed.href : "#"; } catch { return "#"; }
};
const date = value => value ? new Date(`${value}T00:00:00`).toLocaleDateString(undefined, { month: "short", year: "numeric" }) : "Credential";

function Compass({ className = "" }) {
  return <svg className={className} width="40" height="40" viewBox="0 0 40 40" fill="none" aria-hidden="true"><circle cx="20" cy="20" r="17" stroke="currentColor" strokeWidth="1" /><path d="m20 5 4 11 11 4-11 4-4 11-4-11-11-4 11-4Z" stroke="currentColor" /><path d="m20 12 3 8-3 8-3-8Z" fill="currentColor" /></svg>;
}

function ExhibitDialog({ selected, onClose, children }) {
  const ref = useRef(null);
  useEffect(() => {
    const previous = document.activeElement;
    ref.current?.focus();
    return () => previous?.isConnected && previous.focus({ preventScroll: true });
  }, []);
  const keyDown = event => {
    if (event.key === "Escape") { event.stopPropagation(); onClose(); }
    if (event.key !== "Tab") return;
    const items = [...ref.current.querySelectorAll('button, a[href], input, textarea, [tabindex="0"]')].filter(item => !item.disabled && item.getClientRects().length);
    const first = items[0], last = items.at(-1);
    if (event.shiftKey && (document.activeElement === first || document.activeElement === ref.current)) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  };
  return <div className="world-dialog-shade" onPointerDown={event => { if (event.target === event.currentTarget) onClose(); }}>
    <section className="world-dialog" data-exhibit={selected} role="dialog" aria-modal="true" aria-labelledby="world-exhibit-title" ref={ref} tabIndex={-1} onKeyDown={keyDown}>
      <div className="world-dialog-heading"><span className="world-kicker">FIELD NOTES / {selected === "help" ? "THE CONTROLS" : places.find(place => place.id === selected)?.symbol}</span><button type="button" className="world-round" aria-label="Close exhibit" onClick={onClose}>×</button></div>
      {children}
    </section>
  </div>;
}

function ExhibitContent({ selected, profile, projects, certifications, loading, error, sendMessage, formStatus }) {
  const [certificateId, setCertificateId] = useState(null);
  useEffect(() => {
    if (certificateId === null) return;
    const backButton = document.querySelector(".world-certificate-view .world-link-button");
    backButton?.focus({ preventScroll: true });
    backButton?.closest(".world-dialog")?.scrollTo({ top: 0 });
  }, [certificateId]);
  const certificate = certifications.find(item => String(item.id) === String(certificateId));
  if (selected === "help") return <><h2 id="world-exhibit-title">Take the scenic route.</h2><p>This is a small island of work, learning, and things I’m curious about. Choose your own pace.</p><dl className="world-controls-list"><div><dt>Overview</dt><dd>Drag to orbit the island. Scroll or pinch to zoom. Click a building or its label to open an exhibit.</dd></div><div><dt>Walk freely</dt><dd>Click the scenery, then use W A S D or the arrow keys. Drag to look around. Q / E turn left / right. Touch users can hold the direction buttons.</dd></div><div><dt>Read an exhibit</dt><dd>Walk near a building and press Enter, or use “Open nearby exhibit”. The destination buttons take you straight there.</dd></div><div><dt>Return & reset</dt><dd>Escape closes an exhibit. “Overview” returns to the island view. “Standard portfolio” opens the regular website.</dd></div></dl><p className="world-small">No sound plays automatically. Decorative motion follows your device’s reduced-motion preference.</p></>;
  if (loading) return <><h2 id="world-exhibit-title">Opening the exhibit…</h2><p role="status">Fetching the latest portfolio content.</p><div className="world-loading-line" /></>;
  if (error) return <><h2 id="world-exhibit-title">A connection is missing.</h2><p role="alert">{error} Please try again shortly. You can still explore the island.</p><a className="world-button" href="/portfolio">Open standard portfolio ↗</a></>;
  if (selected === "about") return <><h2 id="world-exhibit-title">{profile?.name || "Grish Pradhan"}</h2><p className="world-role">{profile?.role}</p><p>{profile?.bio || "More about me is coming soon."}</p><dl className="world-facts"><div><dt>Based in</dt><dd>{profile?.location || "Nepal"}</dd></div><div><dt>In the gallery</dt><dd>{certifications.length} credentials</dd></div></dl><div className="world-text-links">{profile?.github && <a href={url(profile.github)} target="_blank" rel="noreferrer">GitHub ↗</a>}{profile?.linkedin && <a href={url(profile.linkedin)} target="_blank" rel="noreferrer">LinkedIn ↗</a>}<a href="/about">Full profile ↗</a></div></>;
  if (selected === "projects") return <><h2 id="world-exhibit-title">From the workshop.</h2><p>Systems, experiments, and the work behind them.</p>{projects.length ? <div className="world-project-list">{projects.map(project => <article key={project.id}>{project.image && <img src={url(project.image)} alt={project.title} loading="lazy" />}<div><span className="world-kicker">{project.featured ? "SELECTED WORK" : "PROJECT"}</span><h3>{project.title}</h3><p>{project.description}</p>{project.tech && <p className="world-small">{project.tech}</p>}<div className="world-text-links">{project.url && <a href={url(project.url)} target="_blank" rel="noreferrer">Open project ↗</a>}{project.github && <a href={url(project.github)} target="_blank" rel="noreferrer">Source code ↗</a>}</div></div></article>)}</div> : <div className="world-empty"><span>Work in progress</span><p>New projects will appear here as they’re published.</p></div>}<a className="world-button" href="/projects">Project archive ↗</a></>;
  if (selected === "certifications") return <><h2 id="world-exhibit-title">Proof of practice.</h2><p>{certificate ? "The original credential, without the crop." : "A collection of courses, certifications, and practical security learning. Select a document to enlarge it."}</p>{certificate ? <div className="world-certificate-view"><button className="world-link-button" type="button" onClick={() => setCertificateId(null)}>← All certificates</button><h3>{certificate.title}</h3><p className="world-small">{certificate.issuer} · {date(certificate.issued_on)}</p>{certificate.image_url ? <a href={url(certificate.image_url)} target="_blank" rel="noreferrer" aria-label="Open full-resolution certificate"><img src={url(certificate.image_url)} alt={`${certificate.title} certificate`} /></a> : <p>Image preview unavailable.</p>}{certificate.description && <p>{certificate.description}</p>}<div className="world-text-links">{certificate.credential_url && <a href={url(certificate.credential_url)} target="_blank" rel="noreferrer">Verify credential ↗</a>}{certificate.document_url && <a href={url(certificate.document_url)} target="_blank" rel="noreferrer">Original PDF ↗</a>}<a href={`/certificate/${encodeURIComponent(certificate.id)}`}>Dedicated page ↗</a></div></div> : certifications.length ? <div className="world-credential-list">{certifications.map((item, i) => <button type="button" key={item.id} onClick={() => setCertificateId(item.id)} aria-label={`Enlarge ${item.title}`}><span className="world-credential-number">{String(i + 1).padStart(2, "0")}</span>{item.image_url && <img src={url(item.image_url)} alt="" loading="lazy" />}<span><strong>{item.title}</strong><small>{item.issuer} · {date(item.issued_on)}</small></span><span aria-hidden="true">↗</span></button>)}</div> : <p>No credentials have been published yet.</p>}<a className="world-button" href="/certifications">Full credential archive ↗</a></>;
  if (selected === "achievements") return <><h2 id="world-exhibit-title">One step at a time.</h2><p>The milestones behind the work. Dates and credentials come straight from the portfolio library.</p><ol className="world-timeline">{[...certifications].sort((a, b) => String(b.issued_on || "").localeCompare(String(a.issued_on || ""))).map(item => <li key={item.id}><time>{date(item.issued_on)}</time><a href={`/certificate/${encodeURIComponent(item.id)}`}>{item.title} ↗</a><span>{item.issuer}</span></li>)}</ol>{!certifications.length && <p>Milestones will appear when credentials are published.</p>}<a className="world-button" href="/achievements">See the timeline ↗</a></>;
  return <><h2 id="world-exhibit-title">Send a signal.</h2><p>Have an idea, a security question, or a project in mind? Leave a note.</p><form className="world-contact-form" onSubmit={sendMessage}><label>Your name<input name="name" autoComplete="name" required maxLength={120} /></label><label>Email<input name="email" type="email" autoComplete="email" required maxLength={254} /></label><label>Your message<textarea name="message" rows={4} required maxLength={5000} /></label><button className="world-button" type="submit" disabled={formStatus === "Sending..."}>{formStatus === "Sending..." ? "Sending…" : "Send message ↗"}</button><p role="status" className="world-small">{formStatus}</p></form></>;
}

export default function PortfolioWorld({ profile, projects, certifications, loading, error, sendMessage, formStatus, privacyOpen, onPrivacyChoice, onOpenPrivacy, privacyOptOut }) {
  const host = useRef(null);
  const scene = useRef(null);
  const markers = useRef({});
  const [ready, setReady] = useState(false);
  const [failed, setFailed] = useState(false);
  const [entered, setEntered] = useState(false);
  const [mode, setMode] = useState("overview");
  const [selected, setSelected] = useState(null);
  const [nearby, setNearby] = useState("");
  const blocked = useRef(true);
  const open = useCallback(id => setSelected(id), []);
  useEffect(() => {
    let cancelled = false;
    const bodyOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    import("./portfolio-world-scene").then(({ createWorld }) => {
      if (cancelled) return;
      try {
        scene.current = createWorld(host.current, { onOpen: open, onLocation: setNearby, markers: markers.current, onFailure: () => setFailed(true) });
        scene.current.setBlocked(blocked.current);
        setReady(true);
      } catch (error) { console.warn("3D portfolio unavailable:", error); setFailed(true); }
    }).catch(() => { if (!cancelled) setFailed(true); });
    return () => { cancelled = true; scene.current?.dispose(); scene.current = null; document.body.style.overflow = bodyOverflow; };
  }, [open]);
  useEffect(() => {
    blocked.current = !entered || Boolean(selected) || privacyOpen;
    scene.current?.setBlocked(blocked.current);
  }, [entered, selected, privacyOpen]);
  useEffect(() => { if (ready) scene.current?.setContent({ certifications }); }, [ready, certifications]);
  const enter = () => { setEntered(true); setMode("overview"); scene.current?.setMode("overview"); scene.current?.focus(); };
  const changeMode = next => { setMode(next); scene.current?.setMode(next); scene.current?.focus(); };
  const visit = id => { setMode("walk"); scene.current?.travel(id); scene.current?.focus(); };
  return <main className={`portfolio-world ${entered ? "world-entered" : "world-intro"}`}>
    <div className="world-scene" ref={host} inert={!entered || Boolean(selected) || privacyOpen ? true : undefined} />
    <div className="world-vignette" aria-hidden="true" />
    <div className="world-hud" inert={selected || privacyOpen ? true : undefined}>
      <header className="world-header"><a href="/" className="world-brand"><Compass /><span>{profile?.name || "Grish Pradhan"}<small>A PERSONAL OBSERVATORY</small></span></a><div className="world-header-links"><a href="/portfolio">Standard portfolio <span aria-hidden="true">↗</span></a><button className="world-round" type="button" aria-label="World controls and help" onClick={() => open("help")}>?</button></div></header>
      {!entered && <section className="world-welcome"><p className="world-kicker">CODE / CURIOSITY / CRAFT</p><h1>A little world.<br /><em>A curious mind.</em></h1><p className="world-introduction">An island for the things I build,<br />the things I learn, and what comes next.</p><p className="world-welcome-role">{profile?.role || "Security research & software development"}</p><div className="world-welcome-actions"><button type="button" className="world-button" onClick={enter} disabled={!ready || failed}>{failed ? "3D unavailable" : ready ? "Explore the island →" : "Preparing the island…"}</button><a href="/portfolio">Or take the direct route ↗</a></div><span className="world-handnote">Take a look around. There’s no wrong way.</span></section>}
      {failed && <div className="world-fallback" role="status"><h2>Take the direct route.</h2><p>Your browser couldn’t start the 3D scene. All portfolio content is still available.</p><div>{places.map(place => <a href={`/${place.id === "achievements" ? "achievements" : place.id}`} key={place.id}>{place.label} ↗</a>)}</div></div>}
      {entered && !failed && <>
        <div className="world-mode" role="group" aria-label="Camera mode"><button type="button" aria-pressed={mode === "overview"} onClick={() => changeMode("overview")}>Island overview</button><button type="button" aria-pressed={mode === "walk"} onClick={() => changeMode("walk")}>Walk freely</button></div>
        <div className="world-markers">{places.map(place => <button type="button" className="world-marker" key={place.id} ref={node => { markers.current[place.id] = node; }} onClick={() => open(place.id)}><span>{place.symbol}</span>{place.name}<b aria-hidden="true">↗</b></button>)}</div>
        {mode === "walk" && nearby && <button type="button" className="world-nearby" onClick={() => open(nearby)}>Open nearby exhibit <span>↗ {places.find(place => place.id === nearby)?.label}</span></button>}
        {mode === "walk" && <div className="world-dpad" role="group" aria-label="Walking controls">{[{ key: "w", label: "Walk forward", text: "↑" }, { key: "a", label: "Walk left", text: "←" }, { key: "s", label: "Walk backward", text: "↓" }, { key: "d", label: "Walk right", text: "→" }, { key: "q", label: "Turn left", text: "↶" }, { key: "e", label: "Turn right", text: "↷" }].map(control => <button key={control.key} type="button" aria-label={control.label} className={`world-key-${control.key}`} onPointerDown={event => { event.currentTarget.setPointerCapture(event.pointerId); scene.current?.move(control.key, true); }} onPointerUp={() => scene.current?.move(control.key, false)} onPointerCancel={() => scene.current?.move(control.key, false)} onKeyDown={event => { if ([" ", "Enter"].includes(event.key)) { event.preventDefault(); scene.current?.move(control.key, true); } }} onKeyUp={() => scene.current?.move(control.key, false)} onBlur={() => scene.current?.move(control.key, false)}>{control.text}</button>)}</div>}
        <nav className="world-destinations" aria-label="Travel to an exhibit"><span className="world-destination-caption">GO SOMEWHERE</span>{places.map(place => <button type="button" key={place.id} onClick={() => visit(place.id)}><small>{place.symbol}</small>{place.label}<span aria-hidden="true">↗</span></button>)}</nav>
      </>}
      <footer className="world-footer"><span>{entered ? mode === "walk" ? "WASD / arrows to move · drag to look" : "Drag to orbit · scroll to zoom · select an exhibit" : "AN EXPLORABLE PORTFOLIO / NEPAL"}</span><button type="button" onClick={onOpenPrivacy}>Privacy choices</button></footer>
    </div>
    {selected && <ExhibitDialog selected={selected} onClose={() => setSelected(null)}><ExhibitContent key={selected} selected={selected} profile={profile} projects={projects} certifications={certifications} loading={loading} error={error} sendMessage={sendMessage} formStatus={formStatus} /></ExhibitDialog>}
    {privacyOpen && <aside className="world-privacy" aria-label="Privacy and analytics choices"><div><strong>Your visit, your choice.</strong><p>{privacyOptOut ? "Your browser requests no tracking. Analytics will stay off." : "Optional analytics records page and broad device information. Exploring the island works without it."}</p></div><div><button type="button" onClick={() => onPrivacyChoice("declined")}>No thanks</button>{!privacyOptOut && <button type="button" onClick={() => onPrivacyChoice("accepted")}>Allow analytics</button>}</div></aside>}
  </main>;
}
