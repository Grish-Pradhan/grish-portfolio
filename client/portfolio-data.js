export function safeUrl(value) {
  if (!value || typeof value !== "string") return "#";
  try {
    const url = new URL(value, "https://www.grishpradhan.com.np");
    return ["http:", "https:"].includes(url.protocol) ? url.href : "#";
  } catch { return "#"; }
}

// Older project records used browser-only `blob:` URLs. Keep those records
// readable while the admin replaces them with a durable public asset.
const projectPreviews = {
  "frozen meat and food mart": "/projects/frozen-meat-food-mart.jpg",
  "forge strength": "/projects/forge-strength.webp"
};

export function projectImage(project) {
  const value = typeof project?.image === "string" ? project.image.trim() : "";
  const title = String(project?.title || "").trim().toLowerCase();
  const fallback = projectPreviews[title] || "";

  if (!value || value.startsWith("blob:") || value.startsWith("data:")) return fallback;
  if (value.startsWith("/") || /^https?:\/\//i.test(value)) return value;
  return fallback;
}

export function credentialDate(value) {
  if (!value) return "Date not listed";
  const date = new Date(`${value}T00:00:00`);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString("en-GB", { month: "short", year: "numeric" });
}

export function sortProjects(projects) {
  return [...projects].sort((a, b) => Number(Boolean(b.featured)) - Number(Boolean(a.featured)));
}

export function filterCredentials(certificates, query, issuer = "all") {
  const needle = query.trim().toLowerCase();
  return certificates.filter(certificate =>
    (issuer === "all" || certificate.issuer === issuer) &&
    `${certificate.title || ""} ${certificate.issuer || ""} ${certificate.description || ""}`.toLowerCase().includes(needle)
  );
}

export const pageTitles = { "/": "Security & software", "/portfolio": "Security & software", "/about": "About", "/projects": "Projects", "/photography": "Photography", "/certifications": "Certifications", "/achievements": "Achievements", "/contact": "Contact", "/world": "Open the casefile" };
