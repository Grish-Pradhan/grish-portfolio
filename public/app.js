const $ = (s) => document.querySelector(s);

async function loadPortfolio() {
  try {
    const [profileRes, projectsRes] = await Promise.all([
      fetch("/api/profile"),
      fetch("/api/projects")
    ]);
    const profile = await profileRes.json();
    const projects = await projectsRes.json();

    document.title = `${profile.name} | Portfolio`;
    $("#heroBio").textContent = profile.bio;
    $("#aboutBio").textContent = profile.bio;
    $("#terminalName").textContent = profile.name.toLowerCase().replace(/\s+/g, "-");
    $("#location").textContent = profile.location || "Lalitpur, Nepal";
    $("#email").textContent = profile.email || "—";
    $("#footerName").textContent = profile.name;
    $("#year").textContent = new Date().getFullYear();

    if (profile.github) $("#github").href = profile.github;
    if (profile.linkedin) $("#linkedin").href = profile.linkedin;

    $("#projectCount").textContent = `${projects.length} project${projects.length === 1 ? "" : "s"}`;

    $("#projectsGrid").innerHTML = projects.map((p, i) => `
      <article class="project">
        <div class="number">0${i + 1}</div>
        <h3>${escapeHtml(p.title)}</h3>
        <p>${escapeHtml(p.description)}</p>
        <div class="tags">
          ${(p.tech || "").split(",").filter(Boolean).map(t => `<span class="tag">${escapeHtml(t.trim())}</span>`).join("")}
        </div>
        <div class="project-links">
          ${p.url ? `<a href="${safeUrl(p.url)}" target="_blank" rel="noreferrer">LIVE ↗</a>` : ""}
          ${p.github ? `<a href="${safeUrl(p.github)}" target="_blank" rel="noreferrer">CODE ↗</a>` : ""}
        </div>
      </article>
    `).join("");
  } catch (err) {
    $("#heroBio").textContent = "Portfolio API is unavailable. Check the container logs.";
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    "&":"&","<":"<",">":">",'"':""","'":"&#039;"
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