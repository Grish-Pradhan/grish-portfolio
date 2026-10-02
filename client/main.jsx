import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

function safeUrl(value) {
  try {
    const url = new URL(value, window.location.origin);
    return ["http:", "https:"].includes(url.protocol) ? url.href : "#";
  } catch {
    return "#";
  }
}

function PortfolioApp() {
  const [profile, setProfile] = useState(null);
  const [projects, setProjects] = useState([]);
  const [menuOpen, setMenuOpen] = useState(false);
  const [formStatus, setFormStatus] = useState("");
  const [loadError, setLoadError] = useState("");
  const [analyticsConsent, setAnalyticsConsent] = useState(() => window.localStorage.getItem("portfolioAnalyticsConsent") || "unknown");
  const [privacyOpen, setPrivacyOpen] = useState(() => window.localStorage.getItem("portfolioAnalyticsConsent") === null);

  useEffect(() => {
    let active = true;
    let loading = false;

    async function refresh() {
      if (loading) return;
      loading = true;
      try {
        const response = await window.portfolioApi("/api/site-data", { cache: "no-store" });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Portfolio data unavailable");
        if (active) {
          setProfile(data.profile);
          setProjects(data.projects || []);
          setLoadError("");
        }
      } catch (error) {
        if (active) setLoadError("Portfolio data is temporarily unavailable.");
        console.error("Could not load portfolio data:", error);
      } finally {
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
    if (analyticsConsent !== "accepted") return;
    const sessionKey = `portfolioVisit:${window.location.pathname}`;
    if (window.sessionStorage.getItem(sessionKey)) return;
    window.sessionStorage.setItem(sessionKey, "recorded");

    let referrerHost = "";
    try {
      referrerHost = document.referrer ? new URL(document.referrer).hostname : "";
    } catch {
      referrerHost = "";
    }

    window.portfolioApi("/api/analytics/visit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        path: window.location.pathname,
        referrerHost,
        consentVersion: "2026-10-02"
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
      const response = await window.portfolioApi("/api/contact", {
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
    window.localStorage.setItem("portfolioAnalyticsConsent", choice);
    setAnalyticsConsent(choice);
    setPrivacyOpen(false);
  }

  const sortedProjects = [...projects].sort((a, b) => Number(Boolean(b.featured)) - Number(Boolean(a.featured)));

  return (
    <>
      <header className="nav">
        <a className="brand" href="#home"><span>◆</span> GRISH PORTFOLIO</a>
        <button className="menu" aria-label="Toggle menu" aria-expanded={menuOpen} onClick={() => setMenuOpen(!menuOpen)}>☰</button>
        <nav className={menuOpen ? "open" : ""}>
          {["Home", "About", "Projects", "Contact"].map((item) => (
            <a key={item} href={`#${item.toLowerCase()}`} onClick={() => setMenuOpen(false)}>{item}</a>
          ))}
        </nav>
      </header>

      <main>
        <section id="home" className="hero section">
          <div className="hero-copy">
            <p className="eyebrow">{profile?.role || "CYBERSECURITY · FORENSICS · SYSTEMS"}</p>
            <h1>Building things<br /><span>that matter.</span></h1>
            <p className="lead">{profile?.bio || loadError || "Loading profile..."}</p>
            <div className="actions">
              <a className="button primary" href="#projects">View Projects</a>
              <a className="button ghost" href="#contact">Let's Talk ↗</a>
            </div>
          </div>
          <div className="hero-card">
            <div className="terminal">
              <div className="dots"><i /><i /><i /></div>
              <div className="code">
                <p><b>$</b> whoami</p>
                <p className="accent">{(profile?.name || "grish-pradhan").toLowerCase().replace(/\s+/g, "-")}</p>
                <p><b>$</b> cat focus.txt</p>
                <p>security + software + automation</p>
                <p><b>$</b> status</p>
                <p className="green">● available for interesting work</p>
              </div>
            </div>
          </div>
        </section>

        <section id="about" className="section split">
          <div>
            <p className="eyebrow">01 / ABOUT</p>
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
              <p className="eyebrow">02 / SELECTED WORK</p>
              <h2>Things I've built.</h2>
            </div>
            <span className="count">{projects.length} project{projects.length === 1 ? "" : "s"}</span>
          </div>
          <div className="projects">
            {sortedProjects.map((project, index) => (
              <article className="project" key={project.id}>
                {project.image && <img className="project-image" src={safeUrl(project.image)} alt={project.title} loading="lazy" />}
                <div className="number">{String(index + 1).padStart(2, "0")}</div>
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
          </div>
        </section>

        <section id="contact" className="section contact">
          <div>
            <p className="eyebrow">03 / CONTACT</p>
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
      </main>

      <footer>
        <span>© {new Date().getFullYear()} {profile?.name || "Grish Pradhan"}</span>
        <div className="socials">
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
            <p>With your permission, we record the page path, visit time, and referring site hostname to show recent traffic in the admin dashboard. We do not store raw IP addresses, precise location, or device fingerprints. You can decline and still use the site.</p>
          </div>
          <div className="privacy-actions">
            <button className="button ghost" type="button" onClick={() => chooseAnalyticsConsent("declined")}>Decline</button>
            <button className="button primary" type="button" onClick={() => chooseAnalyticsConsent("accepted")}>Allow analytics</button>
          </div>
        </aside>
      )}
    </>
  );
}

createRoot(document.getElementById("root")).render(<PortfolioApp />);