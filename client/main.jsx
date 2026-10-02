import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

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

function PortfolioApp() {
  const [profile, setProfile] = useState(null);
  const [projects, setProjects] = useState([]);
  const [menuOpen, setMenuOpen] = useState(false);
  const [formStatus, setFormStatus] = useState("");
  const [loadError, setLoadError] = useState("");
  const [analyticsConsent, setAnalyticsConsent] = useState(() => {
    if (browserPrivacyOptOut()) return "declined";
    const savedChoice = window.localStorage.getItem("portfolioAnalyticsConsent");
    if (savedChoice === `${analyticsConsentVersion}:accepted`) return "accepted";
    if (savedChoice === `${analyticsConsentVersion}:declined`) return "declined";
    return "unknown";
  });
  const [privacyOpen, setPrivacyOpen] = useState(() => {
    if (browserPrivacyOptOut()) return false;
    const savedChoice = window.localStorage.getItem("portfolioAnalyticsConsent");
    return ![`${analyticsConsentVersion}:accepted`, `${analyticsConsentVersion}:declined`].includes(savedChoice);
  });

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

    window.portfolioApi("/api/analytics/visit", {
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
    if (choice === "accepted" && browserPrivacyOptOut()) return;
    window.localStorage.setItem("portfolioAnalyticsConsent", `${analyticsConsentVersion}:${choice}`);
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
    </>
  );
}

createRoot(document.getElementById("root")).render(<PortfolioApp />);