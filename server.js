const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase configuration - connect to PostgreSQL via environment variables
// Support both NEXT_PUBLIC_ prefixed and legacy variable names for flexibility
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY;

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
  max: 100,
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
app.use(express.static("public", {
  setHeaders: (res, path) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
  }
}));

// Health check
app.get("/", (req, res) => {
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
  const adminToken = process.env.ADMIN_TOKEN || "change-this-to-a-secret-token";
  if (token !== adminToken) {
    return res.status(401).json({ error: "Admin token required" });
  }
  next();
}

// Admin routes
app.get("/api/admin/messages", checkAdminToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("messages")
      .select("*")
      .order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
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
      .update({ name, role, bio, location, email, github, linkedin, website })
      .eq("id", 1)
      .select()
      .single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Serve admin page
app.get("/admin", (req, res) => {
  res.sendFile("admin/index.html", { root: "public" });
});
app.get("/admin/admin.css", (req, res) => {
  res.sendFile("admin/admin.css", { root: "public" });
});
app.get("/admin/admin.js", (req, res) => {
  res.sendFile("admin/admin.js", { root: "public" });
});

// Serve main app
app.use((req, res) => {
  if (req.path.startsWith("/admin")) {
    return res.status(404).send("Admin page not found");
  }
  res.sendFile("index.html", { root: "public" });
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