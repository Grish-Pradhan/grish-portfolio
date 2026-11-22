import React, { useEffect, useMemo, useRef, useState } from "react";
import { ThemeToggle } from "./theme";
import { credentialDate, filterCredentials, safeUrl, sortProjects } from "./portfolio-data";

export function Icon({ type = "arrow", ...props }) {
  const paths = {
    arrow: <path d="M5 19 19 5M5 5h14v14" />,
    code: <><path d="m8 7-5 5 5 5m8-10 5 5-5 5m-3-14-2 18" /></>,
    shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z" /><path d="m8 12 3 3 5-6" /></>,
    search: <><circle cx="10.5" cy="10.5" r="6.5" /><path d="m16 16 5 5M8 10.5h5m-2.5-2.5v5" /></>,
    island: <><path d="M2 19c3-3 5 3 8 0s5 3 8 0 4 0 4 0M5 15l4-6 3 4 3-3 4 5M12 11V3m0 0 5 3h-5" /></>,
    menu: <path d="M4 8h16M4 16h16" />,
    close: <path d="m6 6 12 12M6 18 18 6" />,
    mail: <><rect x="3" y="5" width="18" height="14" rx="2" /><path d="m3 6 9 7 9-7" /></>
  };
  return <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>{paths[type] || paths.arrow}</svg>;
}

const links = [["Home", "/"], ["About", "/about"], ["Projects", "/projects"], ["Credentials", "/certifications"], ["Achievements", "/achievements"], ["Contact", "/contact"]];

export function SiteHeader({ profile, route }) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef(null);
  const toggleRef = useRef(null);
  useEffect(() => {
    if (!open) return;
    const dismiss = event => {
      if (event.type === "keydown" && event.key === "Escape") { setOpen(false); toggleRef.current?.focus(); }
      if (event.type === "pointerdown" && !menuRef.current?.contains(event.target) && !toggleRef.current?.contains(event.target)) setOpen(false);
    };
    document.addEventListener("keydown", dismiss);
    document.addEventListener("pointerdown", dismiss);
    return () => { document.removeEventListener("keydown", dismiss); document.removeEventListener("pointerdown", dismiss); };
  }, [open]);
  return <>
    <a className="skip-link" href="#main-content">Skip to content</a>
    <header className="nav">
      <a className="brand" href="/" aria-label={`${profile?.name || "Grish Pradhan"} home`}><span className="brand-mark" aria-hidden="true">g<span>p.</span></span><span>{profile?.name || "Grish Pradhan"}<small>Security researcher & developer</small></span></a>
      <nav id="site-navigation" ref={menuRef} className={open ? "open" : ""} aria-label="Main navigation">{links.map(([name, href]) => <a key={href} href={href} aria-current={(href === "/" && ["/", "/portfolio"].includes(route)) || route === href || (href === "/certifications" && route.startsWith("/certificate/")) ? "page" : undefined}>{name}</a>)}</nav>
      <div className="nav-controls"><ThemeToggle /><button ref={toggleRef} className="menu" type="button" aria-label={open ? "Close navigation" : "Open navigation"} aria-controls="site-navigation" aria-expanded={open} onClick={() => setOpen(value => !value)}><Icon type={open ? "close" : "menu"} /></button></div>
    </header>
  </>;
}

export function SiteFooter({ profile, onOpenPrivacy }) {
  return <footer className="site-footer"><div className="footer-top"><a className="footer-name" href="/">{profile?.name || "Grish Pradhan"}<span>Always curious. Always building.</span></a><div className="footer-links"><a href="/world">Open the casefile <Icon type="island" /></a>{profile?.github && <a href={safeUrl(profile.github)} target="_blank" rel="noreferrer">GitHub <Icon /></a>}{profile?.linkedin && <a href={safeUrl(profile.linkedin)} target="_blank" rel="noreferrer">LinkedIn <Icon /></a>}</div></div><div className="footer-bottom"><span>© {new Date().getFullYear()} {profile?.name || "Grish Pradhan"}</span><span>{profile?.location || "Nepal"}</span><button type="button" onClick={onOpenPrivacy}>Privacy choices</button></div></footer>;
}

function SectionHead({ number, label, title, href, action }) {
  return <div className="section-head"><div><p className="eyebrow"><span>{number}</span> {label}</p><h2>{title}</h2></div>{href && <a className="text-link" href={href}>{action} <Icon /></a>}</div>;
}

function PageIntro({ number, label, title, children }) {
  return <div className="page-intro"><a className="back-link" href="/">← Back home</a><p className="eyebrow"><span>{number}</span> {label}</p><h1>{title}</h1><p className="page-description">{children}</p></div>;
}

export function DataState({ loading, error, empty, children }) {
  if (loading) return <div className="data-state" role="status"><span className="loading-line" />Loading portfolio…</div>;
  if (error) return <div className="data-state"><strong>Temporarily unavailable</strong><p>The connection to the portfolio could not be completed. Please use Retry above.</p></div>;
  if (empty) return <div className="data-state"><strong>More to come.</strong><p>New work will appear here when it’s published.</p></div>;
  return children;
}

function ProjectArtwork({ index }) {
  const artifact = index % 3;
  return <div className={`project-artwork artifact-${artifact}`} aria-hidden="true">
    <div className="artifact-noise" />
    {artifact === 0 && <div className="artifact-terminal">
      <div className="artifact-window-bar"><span /><span /><span /><b>CASEFILE / GP-{String(index + 1).padStart(2, "0")}</b></div>
      <div className="artifact-terminal-body"><p><i>$</i> trace --target portfolio.local</p><p className="ok">[ok] trust boundary mapped</p><p><i>$</i> inspect --surface <b>web</b></p><p className="warn">[!] exposed signal: 03 findings</p><p><i>$</i> ship --with <b>care</b><span className="artifact-cursor" /></p></div>
      <span className="artifact-stamp">LIVE TRACE</span>
    </div>}
    {artifact === 1 && <div className="artifact-evidence">
      <div className="evidence-header"><b>INCIDENT / 0084</b><span>REVIEWED</span></div>
      <div className="evidence-main"><div className="evidence-id">GP</div><div><p>IDENTITY / VERIFIED</p><strong>ATTACK SURFACE<br />REPORT</strong><small>hash 7e4c…a91f</small></div></div>
      <div className="evidence-checks"><span>AUTH</span><span>INPUT</span><span>LOGGING</span><span>PATCHED</span></div>
      <span className="artifact-stamp">EVIDENCE / 02</span>
    </div>}
    {artifact === 2 && <div className="artifact-packet">
      <div className="packet-header"><span>PACKET CAPTURE</span><b>ENCRYPTED</b></div>
      <div className="packet-lines"><span /><span /><span /><span /><span /><span /></div>
      <div className="packet-footer"><strong>03:17:42</strong><span>TCP / TLS / DNS</span></div>
      <div className="packet-beacon"><i /><i /><i /></div>
      <span className="artifact-stamp">SIGNAL / CLEAN</span>
    </div>}
    <span className="artifact-label">{["SECURITY / ENGINEERING", "FORENSICS / ANALYSIS", "NETWORK / SIGNAL"][artifact]}</span>
  </div>;
}

function ProjectCard({ project, index }) {
  return <article className={`project ${project.featured ? "featured" : ""}`}>
    <div className="project-media">{project.image ? <img src={safeUrl(project.image)} alt={project.title} loading="lazy" width="600" height="340" /> : <ProjectArtwork index={index} />}</div>
    <div className="project-body"><div className="project-top"><span className="mono">PROJECT / {String(index + 1).padStart(2, "0")}</span>{project.featured && <span className="featured-label">Selected work</span>}</div><h3>{project.title}</h3><p>{project.description}</p><div className="tags">{(project.tech || "").split(",").map(item => item.trim()).filter(Boolean).map((tech, i) => <span key={`${tech}-${i}`}>{tech}</span>)}</div><div className="project-links">{project.url && <a href={safeUrl(project.url)} target="_blank" rel="noreferrer">Open project <Icon /></a>}{project.github && <a href={safeUrl(project.github)} target="_blank" rel="noreferrer">Source code <Icon type="code" /></a>}</div></div>
  </article>;
}

function CertificateCard({ certificate }) {
  return <a className="credential-card" href={`/certificate/${encodeURIComponent(certificate.id)}`}><div className="credential-art">{certificate.image_url ? <img src={safeUrl(certificate.image_url)} alt={`${certificate.title} certificate preview`} loading="lazy" width="600" height="420" /> : <span className="credential-document"><Icon type="shield" width="44" height="44" />Credential document</span>}<span className="credential-open"><Icon /><span>View certificate</span></span></div><div className="credential-copy"><span className="mono">{certificate.issuer}</span><h3>{certificate.title}</h3><div><span>{credentialDate(certificate.issued_on)}</span><Icon /></div></div></a>;
}

function ContactForm({ sendMessage, formStatus }) {
  const pending = formStatus === "Sending...";
  return <form className="contact-form" onSubmit={sendMessage} aria-busy={pending}><div className="form-row"><label>Your name<input name="name" autoComplete="name" maxLength="150" required placeholder="Name" /></label><label>Email address<input type="email" name="email" autoComplete="email" maxLength="254" required placeholder="you@example.com" /></label></div><label>What’s on your mind?<textarea name="message" rows="5" maxLength="10000" required placeholder="A project, a question, or just a hello…" /></label><div className="form-submit"><button className="button primary" type="submit" disabled={pending}>{pending ? "Sending…" : "Send message"} <Icon /></button><span>Your details are only used to reply.</span></div><p className="form-status" role="status">{formStatus}</p></form>;
}

function ContactBlock({ profile, sendMessage, formStatus, standalone = false }) {
  return <section className={`contact-section section ${standalone ? "standalone-contact" : ""}`} id="contact"><div className="contact-copy">{!standalone && <p className="eyebrow"><span>05</span> Say hello</p>}<h2>Good things start<br />with a <em>conversation.</em></h2><p>A useful idea, a tricky problem, or a new perspective. I’d like to hear about it.</p>{profile?.email && <a className="contact-email" href={`mailto:${profile.email}`}><Icon type="mail" />{profile.email}</a>}<span className="contact-location">Based in {profile?.location || "Nepal"} · Connected everywhere.</span></div><ContactForm sendMessage={sendMessage} formStatus={formStatus} /></section>;
}

function FocusAreas() {
  return <div className="focus-grid">{[
    ["shield", "01", "Threat research", "Reading systems like evidence: mapping trust boundaries, attack paths, and the details most people miss."],
    ["code", "02", "Security tooling", "Building dependable software for the moment when a clean interface meets a messy real-world system."],
    ["search", "03", "Continuous practice", "Labs, certifications, and experiments that turn curiosity into sharper instincts and better decisions."]
  ].map(([icon, number, title, copy]) => <article className="focus-card" key={number}><div><Icon type={icon} width="28" height="28" /><span className="mono">{number}</span></div><h3>{title}</h3><p>{copy}</p></article>)}</div>;
}

function HomePage({ profile, projects, certifications, loading, error, sendMessage, formStatus }) {
  return <>
    <section className="hero section"><div className="hero-copy"><p className="eyebrow"><span className="status-dot" /> {profile?.location || "Nepal"} / Independent portfolio</p><p className="hero-name">Hi, I’m {profile?.name || "Grish Pradhan"}.</p><h1>I build systems.<br /><em>I question everything.</em></h1><p className="hero-role">{profile?.role || "Security researcher & full-stack developer"}</p><p className="hero-summary">Security research, software, and ideas with sharp edges.</p><div className="actions"><a className="button primary" href="/projects">See the work <Icon /></a><a className="button secondary" href="/contact">Start a conversation <Icon type="mail" /></a></div><div className="hero-footnote"><span className="mono">SECURITY × SOFTWARE × CURIOSITY</span><a href="#selected-work">Scroll to discover <span aria-hidden="true">↓</span></a></div></div><aside className="hero-note" aria-label="Current focus"><div className="hero-note-label mono">CURRENT FOCUS</div><p className="hero-note-copy">I don’t chase trends. I build systems worth trusting.</p><div className="hero-note-list"><div><span className="mono">01</span><strong>Security research</strong></div><div><span className="mono">02</span><strong>Full-stack systems</strong></div><div><span className="mono">03</span><strong>{profile?.location || "Nepal"}</strong></div></div></aside></section>
    <div className="portfolio-strip"><div><span>Research.</span><span>Build.</span><span>Understand.</span></div><a href="/world"><Icon type="island" /> Open the casefile <Icon /></a></div>
    <section className="section about-section" id="about"><SectionHead number="01" label="A little context" title={<>Curiosity is the<br />starting point.</>} href="/about" action="More about me" /><div className="about-summary"><p>{profile?.bio || "I’m interested in the details behind the interface: how software works, where trust breaks down, and what we can do about it."}</p><div className="real-stats"><div><strong>{loading || error ? "—" : String(projects.length).padStart(2, "0")}</strong><span>Published projects</span></div><div><strong>{loading || error ? "—" : String(certifications.length).padStart(2, "0")}</strong><span>Earned credentials</span></div><div><strong><Icon type="code" width="34" height="34" /></strong><span>Security-minded engineering</span></div></div></div><FocusAreas /></section>
    <section className="section work-section" id="selected-work"><SectionHead number="02" label="Selected work" title={<>Ideas, made real.</>} href="/projects" action="All projects" /><DataState loading={loading} error={error} empty={!projects.length}><div className="projects">{sortProjects(projects).slice(0, 4).map((project, index) => <ProjectCard key={project.id} project={project} index={index} />)}</div></DataState></section>
    <section className="section credentials-section"><SectionHead number="03" label="Learning, documented" title={<>Practice with purpose.</>} href="/certifications" action="All credentials" /><DataState loading={loading} error={error} empty={!certifications.length}><div className="credential-grid">{[...certifications].sort((a, b) => String(b.issued_on || "").localeCompare(String(a.issued_on || ""))).slice(0, 3).map(certificate => <CertificateCard key={certificate.id} certificate={certificate} />)}</div></DataState></section>
    <section className="section island-invitation"><div className="world-portal" aria-hidden="true"><div className="portal-sky"><div className="portal-terminal"><div className="portal-terminal-top"><span className="portal-led" /><span>FIELD CONSOLE / GP-01</span><b>READ ONLY</b></div><div className="portal-terminal-body"><div className="portal-terminal-line"><span>01</span><b>observe</b><i>the system before touching it</i></div><div className="portal-terminal-line"><span>02</span><b>map</b><i>trust boundaries and weak signals</i></div><div className="portal-terminal-line"><span>03</span><b>build</b><i>tools that make the next decision clearer</i></div><div className="portal-terminal-line active"><span>04</span><b>enter_world</b><i>walkable archive <span className="artifact-cursor" /></i></div></div><div className="portal-terminal-foot"><span>STATUS / OBSERVING</span><strong>NEPAL · 27.7172° N</strong></div></div><span className="portal-data-stream stream-one">01001101 00110010 11001010</span><span className="portal-data-stream stream-two">AUTH / TRACE / VERIFY</span><span className="portal-evidence-tag">EVIDENCE<br /><b>GP / 01</b></span></div><div className="portal-meta"><span>WALKABLE ARCHIVE <b>·</b> LIVE CASEFILE</span><span>OPEN THE WORLD <b>↗</b></span></div></div><div><p className="eyebrow"><span>04</span> The other entrance</p><h2>A portfolio you<br />can <em>investigate.</em></h2><p>The same work and credentials, reframed as a living casefile. Move through the world, open the evidence, and follow the signal.</p><a className="button secondary" href="/world">Enter the world <Icon type="island" /></a></div></section>
    <ContactBlock profile={profile} sendMessage={sendMessage} formStatus={formStatus} />
  </>;
}

function CertificationsPage({ certifications, loading, error }) {
  const [query, setQuery] = useState("");
  const [issuer, setIssuer] = useState("all");
  const filtered = useMemo(() => filterCredentials(certifications, query, issuer), [certifications, query, issuer]);
  const issuers = [...new Set(certifications.map(item => item.issuer).filter(Boolean))].sort();
  return <section className="section archive-page"><PageIntro number="03" label="Credential archive" title={<>Learning is<br /><em>an ongoing practice.</em></>}>A record of security certifications, technical courses, and practical learning. Open any credential to see the full certificate.</PageIntro><div className="archive-tools"><label>Search credentials<input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search by title or issuer…" /></label><label>Issuing organisation<select value={issuer} onChange={event => setIssuer(event.target.value)}><option value="all">All organisations</option>{issuers.map(name => <option key={name}>{name}</option>)}</select></label><span role="status">{loading ? "Loading…" : `${filtered.length} credential${filtered.length === 1 ? "" : "s"}`}</span></div><DataState loading={loading} error={error} empty={!certifications.length}>{filtered.length ? <div className="credential-grid">{filtered.map(certificate => <CertificateCard key={certificate.id} certificate={certificate} />)}</div> : <div className="data-state"><strong>No matching credentials.</strong><p>Try a different search or organisation.</p><button className="button secondary" type="button" onClick={() => { setQuery(""); setIssuer("all"); }}>Clear filters</button></div>}</DataState></section>;
}

function CertificateDetail({ certifications, loading, error, id }) {
  const certificate = certifications.find(item => String(item.id) === id);
  return <section className="section certificate-detail"><a className="back-link" href="/certifications">← All credentials</a><DataState loading={loading} error={error}>{certificate ? <><div className="detail-intro"><p className="eyebrow">CREDENTIAL / {certificate.issuer}</p><h1>{certificate.title}</h1><p className="page-description">{credentialDate(certificate.issued_on)}</p></div><div className="certificate-viewer"><div className="certificate-toolbar"><span className="mono">FULL DOCUMENT PREVIEW</span><div>{certificate.credential_url && <a href={safeUrl(certificate.credential_url)} target="_blank" rel="noreferrer">Verify credential <Icon /></a>}{certificate.document_url && <a href={safeUrl(certificate.document_url)} target="_blank" rel="noreferrer">Original document <Icon /></a>}</div></div>{certificate.image_url ? <a className="full-certificate" href={safeUrl(certificate.image_url)} target="_blank" rel="noreferrer" aria-label="Open full-resolution certificate in a new tab"><img src={safeUrl(certificate.image_url)} alt={`${certificate.title}, issued to ${certificate.name || "Grish Pradhan"}`} /><span>Open full resolution <Icon /></span></a> : <div className="data-state">No image preview is available. Use the original document link, if listed.</div>}</div>{certificate.description && <p className="detail-description">{certificate.description}</p>}</> : <div className="data-state"><h1>Certificate not found.</h1><p>This credential may have been moved or removed.</p><a className="text-link" href="/certifications">Browse available credentials <Icon /></a></div>}</DataState></section>;
}

function AchievementsPage({ projects, certifications, loading, error }) {
  const milestones = [...certifications].sort((a, b) => String(b.issued_on || "").localeCompare(String(a.issued_on || "")));
  return <section className="section archive-page"><PageIntro number="04" label="Progress, not a finish line" title={<>Small steps.<br /><em>Lasting progress.</em></>}>A timeline of credentials earned and practical learning. The work continues.</PageIntro><DataState loading={loading} error={error}><div className="real-stats achievement-stats"><div><strong>{projects.length}</strong><span>Published projects</span></div><div><strong>{certifications.length}</strong><span>Credentials earned</span></div></div><div className="timeline">{milestones.map(item => <a className="timeline-item" href={`/certificate/${encodeURIComponent(item.id)}`} key={item.id}><time>{credentialDate(item.issued_on)}</time><div><span className="mono">{item.issuer}</span><h2>{item.title}</h2></div><Icon /></a>)}</div>{!milestones.length && <div className="data-state">Published milestones will appear here.</div>}</DataState></section>;
}

export function PortfolioPages({ route, profile, projects, certifications, loading, error, sendMessage, formStatus }) {
  if (["/", "/portfolio"].includes(route)) return <HomePage {...{ profile, projects, certifications, loading, error, sendMessage, formStatus }} />;
  if (route === "/certifications") return <CertificationsPage {...{ certifications, loading, error }} />;
  if (route.startsWith("/certificate/")) return <CertificateDetail {...{ certifications, loading, error }} id={route.split("/")[2]} />;
  if (route === "/achievements") return <AchievementsPage {...{ projects, certifications, loading, error }} />;
  if (route === "/projects") return <section className="section archive-page"><PageIntro number="02" label="Project index" title={<>From a question<br /><em>to a working thing.</em></>}>Security tools, software experiments, and systems built to solve real problems.</PageIntro><DataState loading={loading} error={error} empty={!projects.length}><div className="projects">{sortProjects(projects).map((project, index) => <ProjectCard key={project.id} {...{ project, index }} />)}</div></DataState></section>;
  if (route === "/about") return <section className="section archive-page"><PageIntro number="01" label="The person behind the work" title={<>A builder’s mindset.<br /><em>A researcher’s curiosity.</em></>}>I’m {profile?.name || "Grish Pradhan"}, based in {profile?.location || "Nepal"}.</PageIntro><DataState loading={loading} error={error}><div className="about-page-grid"><p className="about-biography">{profile?.bio || "I explore how software works and build tools to make it better."}</p><dl className="about-facts"><div><dt>Current focus</dt><dd>{profile?.role || "Security & software"}</dd></div><div><dt>Based in</dt><dd>{profile?.location || "Nepal"}</dd></div>{profile?.email && <div><dt>Get in touch</dt><dd><a href={`mailto:${profile.email}`}>{profile.email}</a></dd></div>}</dl></div></DataState><FocusAreas /><a className="button primary" href="/contact">Start a conversation <Icon /></a></section>;
  if (route === "/contact") return <><div className="section contact-intro"><PageIntro number="05" label="Contact" title={<>Let’s make<br /><em>something worthwhile.</em></>}>For projects, security research, collaboration, or an interesting conversation.</PageIntro></div><ContactBlock {...{ profile, sendMessage, formStatus }} standalone /></>;
  return <section className="section not-found"><p className="eyebrow">404 / Off the map</p><h1>Nothing here.<br /><em>Plenty to explore.</em></h1><p>This page doesn’t exist, but the portfolio does.</p><a className="button primary" href="/">Back to the portfolio <Icon /></a></section>;
}
