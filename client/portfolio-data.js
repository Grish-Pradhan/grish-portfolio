export function safeUrl(value) {
  if (!value || typeof value !== "string") return "#";
  try {
    const url = new URL(value, "https://www.grishpradhan.com.np");
    return ["http:", "https:"].includes(url.protocol) ? url.href : "#";
  } catch { return "#"; }
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

export const pageTitles = { "/": "Security & software", "/portfolio": "Security & software", "/about": "About", "/projects": "Projects", "/certifications": "Certifications", "/achievements": "Achievements", "/contact": "Contact", "/world": "Explore the island" };
