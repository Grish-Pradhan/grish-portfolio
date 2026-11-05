import React, { lazy, Suspense, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { PortfolioPages, SiteFooter, SiteHeader } from "./PortfolioPages";
import { pageTitles, sortProjects } from "./portfolio-data";
const PortfolioWorld = lazy(() => import("./PortfolioWorld"));

// The same existing API powers both presentations and the admin dashboard.
const portfolioRequest = (path, options = {}) => {
  if (typeof window.portfolioApi === "function") return window.portfolioApi(path, options);
  const url = new URL("https://kqdrhwdidjrdbmwteuom.supabase.co/functions/v1/portfolio-api");
  url.searchParams.set("path", path);
  const headers = new Headers(options.headers || {});
  headers.set("apikey", "sb_publishable_Nmyw4pDaqtHNTfuYCmoA3A_aFgn8tZ3");
  return fetch(url, { ...options, headers });
};

const analyticsConsentVersion = "2026-10-02-v3";
const readConsent = () => {
  try {
    const choice = localStorage.getItem("portfolioAnalyticsConsent");
    if (choice === `${analyticsConsentVersion}:accepted`) return "accepted";
    if (choice === `${analyticsConsentVersion}:declined`) return "declined";
  } catch { /* The portfolio still works when browser storage is blocked. */ }
  return "unknown";
};

function browserPrivacyOptOut() {
  return navigator.doNotTrack === "1" || navigator.doNotTrack === "yes" || window.doNotTrack === "1" || navigator.globalPrivacyControl === true;
}

// Retain the established, opt-in coarse analytics contract. No new tracking.
function visitorBrowserMetadata() {
  const ua = navigator.userAgent || "";
  const match = ua.match(/Edg\/([\d.]+)|Firefox\/([\d.]+)|Chrome\/([\d.]+)|Version\/([\d.]+).*Safari/);
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Other";
  const platform = navigator.userAgentData?.platform || navigator.platform || ua;
  const operatingSystem = /Android/i.test(platform) ? "Android" : /iPhone|iPad|iPod/i.test(ua) || (/MacIntel/i.test(platform) && navigator.maxTouchPoints > 1) ? "iOS" : /Win/i.test(platform) ? "Windows" : /Mac/i.test(platform) ? "macOS" : /Chrome OS|CrOS/i.test(`${platform} ${ua}`) ? "ChromeOS" : /Linux/i.test(platform) ? "Linux" : "Other";
  const deviceType = navigator.userAgentData?.mobile || /Android|iPhone|iPod|Mobile/i.test(ua) ? "Mobile" : /iPad|Tablet/i.test(ua) ? "Tablet" : "Desktop";
  const cpu = navigator.hardwareConcurrency || 0;
  const memory = navigator.deviceMemory || 0;
  const width = Math.max(screen.width || 0, screen.height || 0);
  const network = navigator.connection?.effectiveType || "unknown";
  return {
    browser, browserVersion:match ? (match.slice(1).find(Boolean) || "").split(".")[0] : "", operatingSystem, deviceType,
    cpuBucket:cpu ? cpu <= 2 ? "1-2" : cpu <= 4 ? "3-4" : cpu <= 8 ? "5-8" : "9+" : "unknown",
    memoryBucket:memory ? memory <= 2 ? "2GB or less" : memory <= 4 ? "4GB" : memory <= 8 ? "8GB" : "16GB+" : "unknown",
    touchCapable:(navigator.maxTouchPoints || 0) > 0, networkType:["slow-2g","2g","3g","4g"].includes(network) ? network : "unknown",
    dataSaver:Boolean(navigator.connection?.saveData), screenBucket:width <= 768 ? "compact" : width <= 1440 ? "standard" : "large",
    pixelRatioBucket:window.devicePixelRatio <= 1 ? "1x" : window.devicePixelRatio <= 2 ? "2x" : "3x+", colorDepthBucket:screen.colorDepth > 24 ? "30-bit+" : "24-bit or less"
  };
}

function PortfolioApp() {
  const [profile, setProfile] = useState(null);
  const [projects, setProjects] = useState([]);
  const [certifications, setCertifications] = useState([]);
  const [portfolioReady, setPortfolioReady] = useState(false);
  const [formStatus, setFormStatus] = useState("");
  const [loadError, setLoadError] = useState("");
  const [retry, setRetry] = useState(0);
  const [analyticsConsent, setAnalyticsConsent] = useState(readConsent);
  const [privacyOpen, setPrivacyOpen] = useState(() => readConsent() === "unknown");
  const [route] = useState(() => window.location.pathname.replace(/\/+$/, "") || "/");
  const sending = useRef(false);
  const hasData = useRef(false);

  useEffect(() => {
    let active = true;
    let busy = false;
    const controller = new AbortController();
    async function refresh() {
      if (busy) return;
      busy = true;
      try {
        const response = await portfolioRequest("/api/site-data", { cache:"no-store", signal:controller.signal });
        const data = await response.json();
        if (!response.ok) throw new Error("Portfolio data unavailable");
        if (active) {
          setProfile(data.profile);
          setProjects(data.projects || []);
          setCertifications(data.certifications || []);
          setLoadError("");
          hasData.current = true;
        }
      } catch (error) {
        if (active && error.name !== "AbortError") setLoadError(hasData.current ? "Updates are temporarily unavailable. Showing the last loaded content." : "Portfolio data is temporarily unavailable.");
      } finally {
        if (active) setPortfolioReady(true);
        busy = false;
      }
    }
    const visibleRefresh = () => { if (!document.hidden) refresh(); };
    refresh();
    const timer = window.setInterval(visibleRefresh, 15000);
    document.addEventListener("visibilitychange", visibleRefresh);
    return () => { active = false; controller.abort(); clearInterval(timer); document.removeEventListener("visibilitychange", visibleRefresh); };
  }, [retry]);

  useEffect(() => {
    if (analyticsConsent !== "accepted" || browserPrivacyOptOut()) return;
    const sessionKey = `portfolioVisit:${window.location.pathname}`;
    try { if (sessionStorage.getItem(sessionKey)) return; sessionStorage.setItem(sessionKey, "recorded"); } catch { return; }
    let referrerHost = "";
    try { referrerHost = document.referrer ? new URL(document.referrer).hostname : ""; } catch { /* No referrer. */ }
    portfolioRequest("/api/analytics/visit", { method:"POST", headers:{ "Content-Type":"application/json" }, body:JSON.stringify({ path:window.location.pathname, referrerHost, language:navigator.language.slice(0,20), timezone:Intl.DateTimeFormat().resolvedOptions().timeZone.slice(0,64), ...visitorBrowserMetadata(), consentVersion:analyticsConsentVersion }) }).catch(() => {});
  }, [analyticsConsent]);

  useEffect(() => {
    const title = route.startsWith("/certificate/") ? certifications.find(item => String(item.id) === route.split("/")[2])?.title || "Credential" : pageTitles[route] || "Page not found";
    document.title = `${title} — ${profile?.name || "Grish Pradhan"}`;
  }, [profile, route, certifications]);

  async function sendMessage(event) {
    event.preventDefault();
    if (sending.current) return;
    sending.current = true;
    setFormStatus("Sending...");
    const form = event.currentTarget;
    try {
      const response = await portfolioRequest("/api/contact", { method:"POST", headers:{ "Content-Type":"application/json" }, body:JSON.stringify(Object.fromEntries(new FormData(form))) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Your message could not be sent. Please try again.");
      setFormStatus("Message received. Thank you for reaching out.");
      form.reset();
    } catch (error) { setFormStatus(error.message || "Unable to send. Your message is still here; please try again."); }
    finally { sending.current = false; }
  }

  function chooseAnalyticsConsent(choice) {
    if (choice === "accepted" && browserPrivacyOptOut()) return;
    try { localStorage.setItem("portfolioAnalyticsConsent", `${analyticsConsentVersion}:${choice}`); } catch { /* Session-only choice is still respected. */ }
    setAnalyticsConsent(choice);
    setPrivacyOpen(false);
  }

  if (route === "/world") return <Suspense fallback={<main className="world-preparing"><p role="status">Preparing the observatory…</p><a href="/">Open portfolio ↗</a></main>}><PortfolioWorld profile={profile} projects={sortProjects(projects)} certifications={certifications} loading={!portfolioReady} error={loadError} sendMessage={sendMessage} formStatus={formStatus} privacyOpen={privacyOpen} onPrivacyChoice={chooseAnalyticsConsent} onOpenPrivacy={() => setPrivacyOpen(true)} privacyOptOut={browserPrivacyOptOut()} /></Suspense>;

  return <div className="standard-portfolio"><SiteHeader profile={profile} route={route} />
    {loadError && <div className="load-error" role="alert"><span>{loadError}</span><button type="button" onClick={() => { setPortfolioReady(false); setRetry(value => value + 1); }}>Retry connection</button></div>}
    <main id="main-content" tabIndex="-1"><PortfolioPages route={route} profile={profile} projects={projects} certifications={certifications} loading={!portfolioReady} error={hasData.current ? "" : loadError} sendMessage={sendMessage} formStatus={formStatus} /></main>
    <SiteFooter profile={profile} onOpenPrivacy={() => setPrivacyOpen(true)} />
    {privacyOpen && <aside className="privacy-consent" role="dialog" aria-label="Privacy and analytics choices"><h2>Your visit, your choice.</h2><p>{browserPrivacyOptOut() ? "Your browser privacy signal disables analytics. No visit data will be collected." : "Optional analytics help understand how the portfolio is used. With permission, we record page and referring-site information, browser and OS family, coarse device and performance groups, language, and timezone. No raw IP addresses, precise location, exact device models, or media-device details are stored. The site works equally well if you decline."}</p><div className="privacy-actions"><button className="button secondary" type="button" onClick={() => chooseAnalyticsConsent("declined")}>Decline</button>{!browserPrivacyOptOut() && <button className="button secondary" type="button" onClick={() => chooseAnalyticsConsent("accepted")}>Allow analytics</button>}</div></aside>}
  </div>;
}

createRoot(document.getElementById("root")).render(<PortfolioApp />);
