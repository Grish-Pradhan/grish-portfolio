const $ = (s) => document.querySelector(s);
let loadingPortfolio = false;
let hasLoadedPortfolio = false;
let lastPortfolioSnapshot = "";

async function loadPortfolio() {
  if (loadingPortfolio) return;
  loadingPortfolio = true;

  try {
    const response = await fetch("/api/site-data", { cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Portfolio data unavailable");
    const { profile, projects } = data;
    const snapshot = JSON.stringify({ profile, projects });
    if (hasLoadedPortfolio && snapshot === lastPortfolioSnapshot) return;

    document.title = `${profile.name} | Portfolio`;
    $("#profileRole").textContent = profile.role || "";
    $("#heroBio").textContent = profile.bio;
    $("#aboutBio").textContent = profile.bio;
    $("#terminalName").textContent = profile.name.toLowerCase().replace(/\s+/g, "-");
    $("#location").textContent = profile.location || "Lalitpur, Nepal";
    $("#email").textContent = profile.email || "—";
    $("#footerName").textContent = profile.name;
    $("#year").textContent = new Date().getFullYear();

    const github = $("#github");
    github.hidden = !profile.github;
    if (profile.github) github.href = safeUrl(profile.github);
    const linkedin = $("#linkedin");
    linkedin.hidden = !profile.linkedin;
    if (profile.linkedin) linkedin.href = safeUrl(profile.linkedin);
    const website = $("#website");
    website.hidden = !profile.website;
    if (profile.website) website.href = safeUrl(profile.website);

    $("#projectCount").textContent = `${projects.length} project${projects.length === 1 ? "" : "s"}`;

    projects.sort((a, b) => Number(Boolean(b.featured)) - Number(Boolean(a.featured)));
    $("#projectsGrid").innerHTML = projects.map((p, i) => `
      <article class="project">
        ${p.image ? `<img class="project-image" src="${safeUrl(p.image)}" alt="${escapeHtml(p.title)}" loading="lazy">` : ""}
        <div class="number">0${i + 1}</div>
        <h3>${escapeHtml(p.title)}</h3>
        <p>${escapeHtml(p.description)}</p>
        <div class="tags">
          ${p.featured ? '<span class="tag featured">FEATURED</span>' : ""}
          ${(p.tech || "").split(",").filter(Boolean).map(t => `<span class="tag">${escapeHtml(t.trim())}</span>`).join("")}
        </div>
        <div class="project-links">
          ${p.url ? `<a href="${safeUrl(p.url)}" target="_blank" rel="noreferrer">LIVE ↗</a>` : ""}
          ${p.github ? `<a href="${safeUrl(p.github)}" target="_blank" rel="noreferrer">CODE ↗</a>` : ""}
        </div>
      </article>
    `).join("");
    hasLoadedPortfolio = true;
    lastPortfolioSnapshot = snapshot;
  } catch (err) {
    if (!hasLoadedPortfolio) $("#heroBio").textContent = "Portfolio data is temporarily unavailable.";
    console.error("Could not load portfolio data:", err);
  } finally {
    loadingPortfolio = false;
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[c]));
}

function safeUrl(value) {
  try {
    const u = new URL(value, window.location.origin);
    return ["http:", "https:"].includes(u.protocol) ? u.href : "#";
  } catch {
    return "#";
  }
}

$("#contactForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = $("#formStatus");
  status.textContent = "Sending...";
  const data = Object.fromEntries(new FormData(e.target));

  try {
    const res = await fetch("/api/contact", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || "Failed to send");
    status.textContent = "Message received. Thank you!";
    e.target.reset();
  } catch (err) {
    status.textContent = err.message;
  }
});

$(".menu").addEventListener("click", () => $("nav").classList.toggle("open"));
document.querySelectorAll("nav a").forEach(a => a.addEventListener("click", () => $("nav").classList.remove("open")));

loadPortfolio();
setInterval(() => {
  if (!document.hidden) loadPortfolio();
}, 15000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) loadPortfolio();
});