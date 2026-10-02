require("dotenv").config();

const express = require("express");
const path = require("node:path");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;
const buildDirectory = path.join(__dirname, "dist");

// Supabase configuration - connect to PostgreSQL via environment variables
// Prefer the server-only key; public keys remain supported for existing setups.
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const supabaseSecretKey = process.env.PORTFOLIO_DB_SECRET_KEY ||
  process.env.SUPABASE_SECRET_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseKey = supabaseSecretKey ||
  process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
  process.env.SUPABASE_PUBLISHABLE_KEY ||
  process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.warn("Supabase environment variables not set");
}
const supabase = createClient(supabaseUrl, supabaseKey);

// Security headers
app.use(helmet());

// Content Security Policy
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://*.supabase.co"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "https://*.supabase.co"],
      frameSrc: ["'self'"],
      fontSrc: ["'self'"],
      mediaSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// CORS
app.use(
  cors({
    origin: process.env.NODE_ENV === "production" ? process.env.FRONTEND_URL : "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "x-admin-token"],
    credentials: true
  })
);

// Parse bodies
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(buildDirectory, {
  setHeaders: (res, path) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
  }
}));

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "online",
    name: "Grish Pradhan Portfolio",
    version: "2.0.0",
    database: "Supabase PostgreSQL"
  });
});

// Admin token verification helper
function checkAdminToken(req, res, next) {
  const token = req.get("x-admin-token") || "";
  const adminToken = process.env.PORTFOLIO_ADMIN_TOKEN || process.env.ADMIN_TOKEN || "change-this-to-a-secret-token";
  if (token !== adminToken) {
    return res.status(401).json({ error: "Admin token required" });
  }
  if (!supabaseSecretKey) {
    return res.status(503).json({ error: "Admin storage requires a server-side Supabase secret key" });
  }
  next();
}

async function getProfile() {
  const { data, error } = await supabase
    .from("profile")
    .select("*")
    .eq("id", 1)
    .maybeSingle();
  if (error) throw error;
  return data || {
    id: 1,
    name: "Grish Pradhan",
    role: "Cybersecurity · Forensics · Systems",
    bio: "I build practical tools and secure systems across cybersecurity, forensics, and software.",
    location: "Lalitpur, Nepal",
    email: "",
    github: "https://github.com/Grish-Pradhan",
    linkedin: "https://www.linkedin.com/in/grish-pradhan-bb60b2279/",
    website: ""
  };
}

async function getProjects() {
  const { data, error } = await supabase
    .from("projects")
    .select("*")
    .order("created_at", { ascending: false });
  if (error) throw error;
  return data || [];
}

async function getMessages() {
  const { data, error } = await supabase
    .from("messages")
    .select("*")
    .order("created_at", { ascending: false });
  if (error) throw error;
  return data || [];
}

async function getVisits() {
  const { data, error } = await supabase
    .from("visits")
    .select("id, path, referrer_host, country_code, browser, language, timezone, consent_version, created_at")
    .order("created_at", { ascending: false })
    .limit(100);
  if (error?.code === "PGRST205" || error?.code === "42P01") return [];
  if (error) throw error;
  return data || [];
}

// Public portfolio data
app.get("/api/site-data", async (req, res) => {
  try {
    const [profile, projects] = await Promise.all([getProfile(), getProjects()]);
    res.set("Cache-Control", "no-store");
    res.json({ profile, projects });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/profile", async (req, res) => {
  try {
    res.set("Cache-Control", "no-store");
    res.json(await getProfile());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/projects", async (req, res) => {
  try {
    res.set("Cache-Control", "no-store");
    res.json(await getProjects());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/projects/:id", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("projects")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: "Project not found" });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/contact", async (req, res) => {
  try {
    if (!supabaseSecretKey) {
      return res.status(503).json({ error: "Contact storage requires a server-side Supabase secret key" });
    }
    const { name, email, message } = req.body || {};
    if (!name || !email || !message) {
      return res.status(400).json({ error: "Name, email and message are required" });
    }
    const { data, error } = await supabase
      .from("messages")
      .insert([{ name, email, message }])
      .select()
      .single();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/analytics/visit", async (req, res) => {
  try {
    const { path: pagePath, referrerHost = "", browser = "", language = "", timezone = "", consentVersion } = req.body || {};
    const countryHeader = req.get("cf-ipcountry") || req.get("x-vercel-ip-country") || "";
    const countryCode = /^[a-z]{2}$/i.test(countryHeader) ? countryHeader.toUpperCase() : "";
    const allowedBrowsers = ["Chrome", "Firefox", "Safari", "Edge", "Other"];
    if (consentVersion !== "2026-10-02-v2" || typeof pagePath !== "string" ||
        !pagePath.startsWith("/") || pagePath.length > 200 || /[?#]/.test(pagePath) ||
        typeof referrerHost !== "string" || referrerHost.length > 253 ||
        (referrerHost && !/^[a-z0-9.-]+$/i.test(referrerHost)) ||
        !allowedBrowsers.includes(browser) || typeof language !== "string" || language.length > 20 ||
        (language && !/^[a-z0-9-]+$/i.test(language)) || typeof timezone !== "string" || timezone.length > 64 ||
        (timezone && !/^[a-z0-9_+-]+(?:\/[a-z0-9_+-]+)*$/i.test(timezone))) {
      return res.status(400).json({ error: "Invalid consented page view" });
    }
    const { error } = await supabase.from("visits").insert([{
      path: pagePath,
      referrer_host: referrerHost.toLowerCase(),
      country_code: countryCode,
      browser,
      language,
      timezone,
      consent_version: consentVersion
    }]);
    if (error) return res.status(500).json({ error: error.message });
    res.status(202).json({ accepted: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin routes
app.get("/api/admin/messages", checkAdminToken, async (req, res) => {
  try {
    res.json(await getMessages());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/admin/messages/:id", checkAdminToken, async (req, res) => {
  try {
    const { name, email, message } = req.body || {};
    if (typeof name !== "string" || typeof email !== "string" || typeof message !== "string" ||
      !name.trim() || !email.trim() || !message.trim()) {
      return res.status(400).json({ error: "Name, email and message required" });
    }
    const { data, error } = await supabase
      .from("messages")
      .update({ name: name.trim(), email: email.trim(), message: message.trim() })
      .eq("id", req.params.id)
      .select("id, name, email, message, created_at")
      .maybeSingle();
    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: "Message not found" });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/admin/messages/:id", checkAdminToken, async (req, res) => {
  try {
    const { error } = await supabase.from("messages").delete().eq("id", req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/admin/dashboard", checkAdminToken, async (req, res) => {
  try {
    const [projects, messages, profile, visits] = await Promise.all([getProjects(), getMessages(), getProfile(), getVisits()]);
    res.set("Cache-Control", "no-store");
    res.json({ projects, messages, profile, visits });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/admin/projects", checkAdminToken, async (req, res) => {
  try {
    const { title, description, tech = "", image = "", url = "", github = "", featured = 0 } = req.body || {};
    if (!title || !description) return res.status(400).json({ error: "Title and description required" });
    const { data, error } = await supabase
      .from("projects")
      .insert([{ title, description, tech, image, url, github, featured: featured ? 1 : 0 }])
      .select()
      .single();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/admin/projects/:id", checkAdminToken, async (req, res) => {
  try {
    const { title, description, tech = "", image = "", url = "", github = "", featured = 0 } = req.body || {};
    const { error } = await supabase
      .from("projects")
      .update({ title, description, tech, image, url, github, featured: featured ? 1 : 0 })
      .eq("id", req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    const { data } = await supabase.from("projects").select("*").eq("id", req.params.id).single();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/admin/projects/:id", checkAdminToken, async (req, res) => {
  try {
    const { error } = await supabase.from("projects").delete().eq("id", req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/admin/profile", checkAdminToken, async (req, res) => {
  try {
    const { name, role, bio, location = "", email = "", github = "", linkedin = "", website = "" } = req.body || {};
    if (!name || !role || !bio) return res.status(400).json({ error: "Name, role and bio required" });
    const { data, error } = await supabase
      .from("profile")
      .upsert({ id: 1, name, role, bio, location, email, github, linkedin, website }, { onConflict: "id" })
      .select()
      .single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Serve the React application for non-API routes.
app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "API endpoint not found" });
  }
  res.sendFile(path.join(buildDirectory, "index.html"), (error) => {
    if (error && !res.headersSent) {
      res.status(503).send("Application build missing. Run npm run build first.");
    }
  });
});

// Start server
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log("Portfolio running on http://0.0.0.0:" + PORT);
  console.log("Database: Supabase PostgreSQL");
});

// Error handling
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Promise rejection:", reason);
  server.close();
});