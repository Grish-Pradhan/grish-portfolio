import React, { lazy, Suspense, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import TechnologyArtifacts from "./TechnologyArtifacts";
const PortfolioWorld = lazy(() => import("./PortfolioWorld"));

const portfolioRequest = (path, options = {}) => {
  if (typeof window.portfolioApi === "function") return window.portfolioApi(path, options);
  const url = new URL("https://kqdrhwdidjrdbmwteuom.supabase.co/functions/v1/portfolio-api");
  url.searchParams.set("path", path);
  const headers = new Headers(options.headers || {});
  headers.set("apikey", "sb_publishable_Nmyw4pDaqtHNTfuYCmoA3A_aFgn8tZ3");
  return fetch(url, { ...options, headers });
};

const analyticsConsentVersion = "2026-10-02-v3";
const visitorBrowserMetadata = () => {
  const userAgent = navigator.userAgent || "";
  const browserMatch = userAgent.match(/Edg\/([\d.]+)|Firefox\/([\d.]+)|Chrome\/([\d.]+)|Version\/([\d.]+).*Safari/);
  const browser = /Edg\//.test(userAgent) ? "Edge"
    : /Firefox\//.test(userAgent) ? "Firefox"
    : /Chrome\//.test(userAgent) ? "Chrome"
    : /Safari\//.test(userAgent) ? "Safari"
    : "Other";
  const browserVersion = browserMatch ? (browserMatch.slice(1).find(Boolean) || "").split(".")[0] : "";
  const platform = navigator.userAgentData?.platform || navigator.platform || userAgent;
  const touchPoints = navigator.maxTouchPoints || 0;
  const operatingSystem = /Android/i.test(platform) ? "Android"
    : /iPhone|iPad|iPod/i.test(userAgent) || (/MacIntel/i.test(platform) && touchPoints > 1) ? "iOS"
    : /Win/i.test(platform) ? "Windows"
    : /Mac/i.test(platform) ? "macOS"
    : /Chrome OS|CrOS/i.test(`${platform} ${userAgent}`) ? "ChromeOS"
    : /Linux/i.test(platform) ? "Linux"
    : "Other";
  const deviceType = navigator.userAgentData?.mobile || /Android|iPhone|iPod|Mobile/i.test(userAgent)
    ? "Mobile"
    : /iPad|Tablet/i.test(userAgent) ? "Tablet" : "Desktop";
  const cpuCores = navigator.hardwareConcurrency || 0;
  const memory = navigator.deviceMemory || 0;
  const screenWidth = Math.max(screen.width || 0, screen.height || 0);
  const effectiveType = navigator.connection?.effectiveType || "unknown";
  return {
    browser,
    browserVersion,
    operatingSystem,
    deviceType,
    cpuBucket: cpuCores ? cpuCores <= 2 ? "1-2" : cpuCores <= 4 ? "3-4" : cpuCores <= 8 ? "5-8" : "9+" : "unknown",
    memoryBucket: memory ? memory <= 2 ? "2GB or less" : memory <= 4 ? "4GB" : memory <= 8 ? "8GB" : "16GB+" : "unknown",
    touchCapable: (navigator.maxTouchPoints || 0) > 0,
    networkType: ["slow-2g", "2g", "3g", "4g"].includes(effectiveType) ? effectiveType : "unknown",
    dataSaver: Boolean(navigator.connection?.saveData),
    screenBucket: screenWidth <= 768 ? "compact" : screenWidth <= 1440 ? "standard" : "large",
    pixelRatioBucket: window.devicePixelRatio <= 1 ? "1x" : window.devicePixelRatio <= 2 ? "2x" : "3x+",
    colorDepthBucket: screen.colorDepth > 24 ? "30-bit+" : "24-bit or less"
  };
};

function browserPrivacyOptOut() {
  return navigator.doNotTrack === "1" || navigator.doNotTrack === "yes" ||
    window.doNotTrack === "1" || navigator.globalPrivacyControl === true;
}

function safeUrl(value) {
  try {
    const url = new URL(value, window.location.origin);
    return ["http:", "https:"].includes(url.protocol) ? url.href : "#";
  } catch {
    return "#";
  }
}

function browserFamily() {
  const userAgent = navigator.userAgent;
  if (/Edg\//.test(userAgent)) return "Edge";
  if (/Firefox\//.test(userAgent)) return "Firefox";
  if (/Chrome\//.test(userAgent)) return "Chrome";
  if (/Safari\//.test(userAgent)) return "Safari";
  return "Other";
}

function formatCredentialDate(value) {
  if (!value) return "Credential";
  const date = new Date(`${value}T00:00:00`);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}


function CertificateDetail({ certificate, loading }) {
  if (loading) {
    return <section className="detail-page section"><a className="back-link" href="/certifications">← Back to certifications</a><div className="detail-intro"><p className="eyebrow">Opening credential</p><h1>Loading<br /><span>certificate.</span></h1><p className="detail-subtitle">Fetching the verified certificate and preview.</p></div><div className="certificate-viewer certificate-viewer-loading" aria-busy="true"><div className="certificate-loading-shimmer" /><p>Preparing certificate preview…</p></div></section>;
  }
  if (!certificate) {
    return <section className="detail-page section"><a className="back-link" href="/certifications">← Back to certifications</a><h1>Certificate not found.</h1></section>;
  }
  return (
    <section className="detail-page section">
      <a className="back-link" href="/certifications">← Back to certifications</a>
      <div className="detail-intro"><p className="eyebrow">VERIFIED CREDENTIAL</p><h1>{certificate.title}</h1><p className="detail-subtitle">{certificate.issuer} · {formatCredentialDate(certificate.issued_on)}</p></div>
      <div className="certificate-viewer">
        <div className="certificate-viewer-toolbar"><span>DOCUMENT PREVIEW</span><div>{certificate.credential_url ? <a href={safeUrl(certificate.credential_url)} target="_blank" rel="noreferrer">Verify ↗</a> : null}{certificate.document_url ? <a href={safeUrl(certificate.document_url)} target="_blank" rel="noreferrer">Open PDF ↗</a> : null}</div></div>
        {certificate.image_url ? <img src={safeUrl(certificate.image_url)} alt={`${certificate.title} certificate`} /> : <div className="certificate-viewer-empty">Preview unavailable. Open the original document above.</div>}
      </div>
      {certificate.description ? <p className="detail-description">{certificate.description}</p> : null}
    </section>
  );
}

function CertificationsPage({ certifications }) {
  return <section className="archive-page section"><a className="back-link" href="/portfolio">← Back home</a><div className="detail-intro"><p className="eyebrow">03 / CREDENTIALS</p><h1>Proof of<br /><span>practice.</span></h1><p className="detail-subtitle">A visual archive of certifications, courses, and practical security learning.</p></div><div className="archive-grid">{certifications.map((cert, index) => <a className="archive-card" href={`/certificate/${cert.id}`} key={cert.id}><span className="archive-number">{String(index + 1).padStart(2, "0")}</span>{cert.image_url ? <img src={safeUrl(cert.image_url)} alt="" loading="lazy" /> : <span className="archive-placeholder">PDF</span>}<div><span>{formatCredentialDate(cert.issued_on)}</span><h2>{cert.title}</h2><p>{cert.issuer}</p></div><b>VIEW CREDENTIAL ↗</b></a>)}</div></section>;
}

function AchievementsPage({ projects, certifications }) {
  const milestones = [...certifications].sort((a, b) => String(b.issued_on || "").localeCompare(String(a.issued_on || "")));
  return <section className="archive-page section"><a className="back-link" href="/portfolio">← Back home</a><div className="detail-intro"><p className="eyebrow">04 / ACHIEVEMENTS</p><h1>Momentum<br /><span>in motion.</span></h1><p className="detail-subtitle">A living timeline of shipped work, security practice, and the habits behind the progress.</p></div><div className="achievement-stats"><div><strong>{projects.length}</strong><span>projects shipped</span></div><div><strong>{certifications.length}</strong><span>credentials earned</span></div><div><strong>24/7</strong><span>learning mindset</span></div></div><div className="timeline">{milestones.map((cert, index) => <a className="timeline-item" href={`/certificate/${cert.id}`} key={cert.id}><span className="timeline-index">{String(index + 1).padStart(2, "0")}</span><span className="timeline-dot" /><div><small>{formatCredentialDate(cert.issued_on)}</small><h2>{cert.title}</h2><p>{cert.issuer}</p></div><b>OPEN ↗</b></a>)}</div></section>;
}

function ProjectsPage({ projects }) {
  const sortedProjects = [...projects].sort((a, b) => Number(Boolean(b.featured)) - Number(Boolean(a.featured)));
  return <section className="archive-page section"><a className="back-link" href="/portfolio">← Back home</a><div className="detail-intro"><p className="eyebrow">02 / Selected work</p><h1>Built for<br /><span>the real world.</span></h1><p className="detail-subtitle">A focused collection of systems, interfaces, and security-minded experiments.</p></div><div className="projects standalone-projects">{sortedProjects.map((project, index) => <article className={`project ${project.featured ? "featured" : ""}`} key={project.id}>{project.image ? <img className="project-image" src={safeUrl(project.image)} alt={project.title} loading="lazy" /> : null}<div className="project-top"><div className="number">{String(index + 1).padStart(2, "0")}</div>{project.featured ? <span className="featured-label">Featured</span> : null}</div><div className="project-icon">{["↗", "⌘", "◌", "✦", "⌁"][index % 5]}</div><h3>{project.title}</h3><p>{project.description}</p><div className="tags">{(project.tech || "").split(",").filter(Boolean).map((tech) => <span className="tag" key={tech}>{tech.trim()}</span>)}</div><div className="project-links">{project.url ? <a href={safeUrl(project.url)} target="_blank" rel="noreferrer">Open project ↗</a> : null}{project.github ? <a href={safeUrl(project.github)} target="_blank" rel="noreferrer">View code ↗</a> : null}</div></article>)}</div></section>;
}

function AboutPage({ profile, certifications, projects }) {
  return <section className="archive-page section"><a className="back-link" href="/portfolio">← Back home</a><div className="detail-intro"><p className="eyebrow">01 / About</p><h1>Curious by<br /><span>default.</span></h1><p className="detail-subtitle">The person behind the systems: a security researcher and full-stack developer based in {profile?.location || "Nepal"}.</p></div><div className="about-page-grid"><div className="about-copy"><p>{profile?.bio || "Building useful, secure software with a bias toward learning in public."}</p></div><div className="facts"><div><small>Location</small><strong>{profile?.location || "Lalitpur, Nepal"}</strong></div><div><small>Credentials</small><strong>{certifications.length} earned</strong></div><div><small>Selected builds</small><strong>{projects.length} shipped</strong></div><div><small>Focus</small><strong>Security + software</strong></div></div></div></section>;
}

function ContactPage({ profile, sendMessage, formStatus }) {
  return <section className="archive-page section contact-page"><a className="back-link" href="/portfolio">← Back home</a><div className="detail-intro"><p className="eyebrow">05 / Contact</p><h1>Start a<br /><span>conversation.</span></h1><p className="detail-subtitle">Have a project, security question, or collaboration in mind? Send a note and I’ll get back to you.</p></div><div className="contact contact-page-grid"><div><p className="muted">{profile?.email || "Email is available through the form."}</p><p className="muted">Prefer a quick hello? Find me on GitHub or LinkedIn below.</p></div><form onSubmit={sendMessage}><label>Name<input name="name" required placeholder="Your name" /></label><label>Email<input type="email" name="email" required placeholder="you@example.com" /></label><label>Message<textarea name="message" rows="6" required placeholder="Tell me about it..." /></label><button className="button primary" type="submit">Send message</button><p className="status" role="status">{formStatus}</p></form></div></section>;
}

function PortfolioApp() {
  const [profile, setProfile] = useState(null);
  const [projects, setProjects] = useState([]);
  const [certifications, setCertifications] = useState([]);
  const [portfolioReady, setPortfolioReady] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [formStatus, setFormStatus] = useState("");
  const [loadError, setLoadError] = useState("");
  const [analyticsConsent, setAnalyticsConsent] = useState(() => {
    const savedChoice = window.localStorage.getItem("portfolioAnalyticsConsent");
    if (savedChoice === `${analyticsConsentVersion}:accepted`) return "accepted";
    if (savedChoice === `${analyticsConsentVersion}:declined`) return "declined";
    return "unknown";
  });
  const [privacyOpen, setPrivacyOpen] = useState(() => {
    const savedChoice = window.localStorage.getItem("portfolioAnalyticsConsent");
    return ![`${analyticsConsentVersion}:accepted`, `${analyticsConsentVersion}:declined`].includes(savedChoice);
  });
  const [route] = useState(() => window.location.pathname.replace(/\/+$/, "") || "/");

  useEffect(() => {
    let active = true;
    let loading = false;

    async function refresh() {
      if (loading) return;
      loading = true;
      try {
        const response = await portfolioRequest("/api/site-data", { cache: "no-store" });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Portfolio data unavailable");
        if (active) {
          setProfile(data.profile);
          setProjects(data.projects || []);
          setCertifications(data.certifications || []);
          setLoadError("");
        }
      } catch (error) {
        if (active) setLoadError("Portfolio data is temporarily unavailable.");
        console.error("Could not load portfolio data:", error);
      } finally {
        if (active) setPortfolioReady(true);
        loading = false;
      }
    }

    const refreshWhenVisible = () => {
      if (!document.hidden) refresh();
    };

    refresh();
    const timer = window.setInterval(refreshWhenVisible, 15000);
    document.addEventListener("visibilitychange", refreshWhenVisible);
    return () => {
      active = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
    };
  }, []);

  useEffect(() => {
    if (analyticsConsent !== "accepted" || browserPrivacyOptOut()) return;
    const sessionKey = `portfolioVisit:${window.location.pathname}`;
    if (window.sessionStorage.getItem(sessionKey)) return;
    window.sessionStorage.setItem(sessionKey, "recorded");

    let referrerHost = "";
    try {
      referrerHost = document.referrer ? new URL(document.referrer).hostname : "";
    } catch {
      referrerHost = "";
    }

    portfolioRequest("/api/analytics/visit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        path: window.location.pathname,
        referrerHost,
        language: navigator.language.slice(0, 20),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone.slice(0, 64),
        ...visitorBrowserMetadata(),
        consentVersion: analyticsConsentVersion
      })
    }).catch((error) => console.warn("Could not record consented visit:", error));
  }, [analyticsConsent]);

  useEffect(() => {
    if (profile?.name) document.title = `${profile.name} | Portfolio`;
  }, [profile]);

  async function sendMessage(event) {
    event.preventDefault();
    setFormStatus("Sending...");
    const form = event.currentTarget;
    const values = Object.fromEntries(new FormData(form));

    try {
      const response = await portfolioRequest("/api/contact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Failed to send message");
      setFormStatus("Message received. Thank you!");
      form.reset();
    } catch (error) {
      setFormStatus(error.message);
    }
  }

  function chooseAnalyticsConsent(choice) {
    if (choice === "accepted" && browserPrivacyOptOut()) return;
    window.localStorage.setItem("portfolioAnalyticsConsent", `${analyticsConsentVersion}:${choice}`);
    setAnalyticsConsent(choice);
    setPrivacyOpen(false);
  }

  const sortedProjects = [...projects].sort((a, b) => Number(Boolean(b.featured)) - Number(Boolean(a.featured)));

  if (route === "/" || route === "/world") {
    return <Suspense fallback={<main style={{ minHeight: "100dvh", display: "grid", placeContent: "center", gap: 18, background: "#faf1df", color: "#293c38" }}><p role="status">Preparing the observatory…</p><a href="/portfolio">Open standard portfolio ↗</a></main>}><PortfolioWorld profile={profile} projects={sortedProjects} certifications={certifications} loading={!portfolioReady} error={loadError} sendMessage={sendMessage} formStatus={formStatus} privacyOpen={privacyOpen} onPrivacyChoice={chooseAnalyticsConsent} onOpenPrivacy={() => setPrivacyOpen(true)} privacyOptOut={browserPrivacyOptOut()} /></Suspense>;
  }

  return (
    <div className="standard-portfolio">
      <header className="nav">
        <a className="brand" href="/portfolio"><span className="brand-mark">GP</span><span>{profile?.name || "Grish Pradhan"}<small>Security & software</small></span></a>
        <div className="nav-meta"><span className="status-dot" /> {profile?.location || "Nepal"}</div>
        <button className="menu" aria-label="Toggle menu" aria-expanded={menuOpen} onClick={() => setMenuOpen(!menuOpen)}>☰</button>
        <nav className={menuOpen ? "open" : ""}>
          {[{ label: "Home", href: "/portfolio" }, { label: "About", href: "/about" }, { label: "Projects", href: "/projects" }, { label: "Certifications", href: "/certifications" }, { label: "Achievements", href: "/achievements" }, { label: "Contact", href: "/contact" }].map((item) => (
            <a key={item.label} href={item.href} aria-current={route === item.href || (item.href === "/certifications" && route.startsWith("/certificate/")) ? "page" : undefined} onClick={() => setMenuOpen(false)}>{item.label}</a>
          ))}
        </nav>
      </header>

      <main>
        {route.match(/^\/certificate\//) ? <CertificateDetail loading={!portfolioReady} certificate={certifications.find((item) => String(item.id) === route.split("/").filter(Boolean)[1])} /> : route === "/certifications" ? <CertificationsPage certifications={certifications} /> : route === "/achievements" ? <AchievementsPage projects={projects} certifications={certifications} /> : route === "/projects" ? <ProjectsPage projects={projects} /> : route === "/about" ? <AboutPage profile={profile} certifications={certifications} projects={projects} /> : route === "/contact" ? <ContactPage profile={profile} sendMessage={sendMessage} formStatus={formStatus} /> : <>
        <section id="home" className="hero section technology-hero">
          <div className="hero-copy">
            <p className="hero-location">{profile?.name || "Grish Pradhan"} / {profile?.location || "Nepal"}</p>
            <h1>Technology,<br />built with<br />security in mind.</h1>
            <p className="role">{profile?.role || "Security researcher & full-stack developer"}</p>
            <p className="lead">{profile?.bio || loadError || "Exploring how systems work, where they break, and how to build them better."}</p>
            <div className="actions">
              <a className="button primary" href="/projects">Explore projects</a>
              <a className="button ghost" href="/contact">Get in touch</a>
            </div>
            <div className="hero-links"><a href="/about">About my work</a><a href="/certifications">Certifications{portfolioReady ? ` (${certifications.length})` : ""}</a></div>
          </div>
          <TechnologyArtifacts />
        </section>

        <section id="about" className="section split">
          <div>
            <p className="eyebrow">01 / About</p>
            <h2>A little about me.</h2>
          </div>
          <div className="about-copy">
            <p>{profile?.bio || loadError || "Loading profile..."}</p>
            <div className="facts">
              <div><small>LOCATION</small><strong>{profile?.location || "Lalitpur, Nepal"}</strong></div>
              <div><small>EMAIL</small><strong>{profile?.email || "—"}</strong></div>
            </div>
          </div>
        </section>

        <section id="projects" className="section">
          <div className="section-head">
            <div>
              <p className="eyebrow">02 / Selected work</p>
              <h2>Things I've built.</h2>
            </div>
            <span className="count">{projects.length} project{projects.length === 1 ? "" : "s"}</span>
          </div>
          <div className="projects">
            {sortedProjects.map((project, index) => (
              <article className={`project ${project.featured ? "featured" : ""}`} key={project.id}>
                {project.image && <img className="project-image" src={safeUrl(project.image)} alt={project.title} loading="lazy" />}
                <div className="project-top"><div className="number">{String(index + 1).padStart(2, "0")}</div>{project.featured ? <span className="featured-label">FEATURED</span> : null}</div>
                <div className="project-icon">{["↗", "⌘", "◌", "✦", "⌁"][index % 5]}</div>
                <h3>{project.title}</h3>
                <p>{project.description}</p>
                <div className="tags">
                  {project.featured ? <span className="tag featured">FEATURED</span> : null}
                  {(project.tech || "").split(",").filter(Boolean).map((tech) => <span className="tag" key={tech}>{tech.trim()}</span>)}
                </div>
                <div className="project-links">
                  {project.url && <a href={safeUrl(project.url)} target="_blank" rel="noreferrer">LIVE ↗</a>}
                  {project.github && <a href={safeUrl(project.github)} target="_blank" rel="noreferrer">CODE ↗</a>}
                </div>
              </article>
            ))}
            {!sortedProjects.length && <div className="empty-state"><strong>Work in progress</strong><p>New projects will appear here as they’re published.</p></div>}
          </div>
        </section>

        <section id="certifications" className="section certifications-section">
          <div className="section-head">
            <div>
              <p className="eyebrow">03 / Credentials</p>
              <h2>Proof of<br /><span>practice.</span></h2>
            </div>
            <span className="count">{certifications.length} credential{certifications.length === 1 ? "" : "s"}</span>
          </div>
          <div className="certifications-grid">
            {certifications.length ? certifications.map((cert) => (
                <article className="certification-card" key={cert.id} role="link" tabIndex="0" onClick={(event) => { if (!event.target.closest("a")) window.location.href = `/certificate/${cert.id}`; }} onKeyDown={(event) => { if (event.key === "Enter") window.location.href = `/certificate/${cert.id}`; }}>
                <div className="certificate-seal">✦</div>
                {cert.image_url ? <img src={safeUrl(cert.image_url)} alt={`${cert.title} certificate`} loading="lazy" /> : null}
                <div className="certificate-copy">
                  <span className="certificate-date">{formatCredentialDate(cert.issued_on)}</span>
                  <h3>{cert.title}</h3>
                  <p className="certificate-issuer">{cert.issuer}</p>
                  {cert.description ? <p>{cert.description}</p> : null}
                  <div className="certificate-actions">
                    <a className="certificate-link" href={`/certificate/${cert.id}`}>VIEW CERTIFICATE ↗</a>
                    {cert.credential_url ? <a className="certificate-link" href={safeUrl(cert.credential_url)} target="_blank" rel="noreferrer">VERIFY CREDENTIAL ↗</a> : null}
                    {cert.document_url ? <a className="certificate-link" href={safeUrl(cert.document_url)} target="_blank" rel="noreferrer">OPEN DOCUMENT ↗</a> : null}
                  </div>
                </div>
                </article>
            )) : <div className="empty-state">Certifications will appear here as they are added.</div>}
          </div>
        </section>

        <section id="contact" className="section contact">
          <div>
              <p className="eyebrow">04 / Contact</p>
            <h2>Let's build<br />something.</h2>
            <p className="muted">Have a project, idea, or collaboration in mind? Send a message.</p>
          </div>
          <form onSubmit={sendMessage}>
            <label>Name<input name="name" required placeholder="Your name" /></label>
            <label>Email<input type="email" name="email" required placeholder="you@example.com" /></label>
            <label>Message<textarea name="message" rows="6" required placeholder="Tell me about it..." /></label>
            <button className="button primary" type="submit">Send Message ↗</button>
            <p className="status" role="status">{formStatus}</p>
          </form>
        </section>
        </>}
      </main>

      <footer>
        <span>© {new Date().getFullYear()} {profile?.name || "Grish Pradhan"}</span>
        <div className="socials">
          <a href="/world">Explore the island ↗</a>
          {profile?.github && <a href={safeUrl(profile.github)} target="_blank" rel="noreferrer">GitHub ↗</a>}
          {profile?.linkedin && <a href={safeUrl(profile.linkedin)} target="_blank" rel="noreferrer">LinkedIn ↗</a>}
          {profile?.website && <a href={safeUrl(profile.website)} target="_blank" rel="noreferrer">Website ↗</a>}
          <button type="button" onClick={() => setPrivacyOpen(true)}>Privacy choices</button>
        </div>
      </footer>

      {privacyOpen && (
        <aside className="privacy-consent" role="dialog" aria-label="Privacy and analytics choices">
          <div>
            <h2>Privacy choices</h2>
            {browserPrivacyOptOut()
              ? <p>Your browser privacy signal disables analytics. No visit data will be collected.</p>
              : <p>With your permission, we record page path, referring site, browser and OS family, device category, coarse CPU/RAM/network/screen groups, language, and timezone. We do not store raw IP addresses, exact device models, GPU details, precise location, media-device labels, or battery state. You can decline and still use the site.</p>}
          </div>
          <div className="privacy-actions">
            <button className="button ghost" type="button" onClick={() => chooseAnalyticsConsent("declined")}>Decline</button>
            {!browserPrivacyOptOut() && <button className="button primary" type="button" onClick={() => chooseAnalyticsConsent("accepted")}>Allow analytics</button>}
          </div>
        </aside>
      )}
    </div>
  );
}

createRoot(document.getElementById("root")).render(<PortfolioApp />);
