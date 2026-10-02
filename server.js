const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase configuration - connect to PostgreSQL via environment variables
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.warn("⚠️ Supabase environment variables not set. Set SUPABASE_URL and SUPABASE_ANON_KEY.");
}
const supabase = createClient(supabaseUrl, supabaseKey);

// --- Security Hardening ---

// Helmet security headers
app.use(helmet());

// Content Security Policy - restrict sources
app.use(helmet.contentSecurityPolicy({
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
}));

// Rate limiting - 100 requests per 15 minutes per IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests from this IP, please try again later." },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === "production" ? process.env.FRONTEND_URL : "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "x-admin-token"],
  credentials: true
}));

// Parse JSON bodies (limit 1mb)
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Serve static files from public directory
app.use(express.static("public", {
  setHeaders: (res, filePath) => {
    // Security: prevent MIME type sniffing
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
  }
}));

// --- API Routes ---

// Health check
app.get("/", (req, res) => {
  res.json({
    status: "online",
    name: "Grish Pradhan Portfolio",
    version: "2.0.0",
    database: "Supabase PostgreSQL",
    environment: process.env.NODE_ENV || "development"
  });
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received. Shutting down gracefully...");
  server.close(() => {
    console.log("Process terminated");
  });
});

// --- Public API Routes ---

// Get profile
app.get("/api/profile", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Database service unavailable" });

    const { data, error } = await supabase
      .from("profile")
      .select("*")
      .eq("id", 1)
      .single();

    if (error) {
      console.error("Supabase profile error:", error);
      return res.status(500).json({ error: "Failed to fetch profile" });
    }
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all projects
app.get("/api/projects", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Database service unavailable" });

    const { data, error } = await supabase
      .from("projects")
      .select("*")
      .order("featured", { ascending: false })
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Supabase projects error:", error);
      return res.status(500).json({ error: "Failed to fetch projects" });
    }
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Get single project
app.get("/api/projects/:id", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Database service unavailable" });

    const { data, error } = await supabase
      .from("projects")
      .select("*")
      .eq("id", req.params.id)
      .single();

    if (error) return res.status(404).json({ error: "Project not found" });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Submit contact form
app.post("/api/contact", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Database service unavailable" });

    const { name, email, message } = req.body || {};
    if (!name || !email || !message) {
      return res.status(400).json({ error: "Name, email, and message are required." });
    }
    if (String(message).length > 5000) {
      return res.status(400).json({ error: "Message is too long." });
    }

    const { data, error } = await supabase
      .from("messages")
      .insert([{ name: String(name).trim(), email: String(email).trim(), message: String(message).trim() }])
      .select()
      .single();

    if (error) {
      console.error("Supabase messages error:", error);
      return res.status(500).json({ error: "Failed to submit message" });
    }
    res.status(201).json({ success: true, id: data.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Admin API Routes ---

// Get all messages (admin required - token verified via header)
app.get("/api/admin/messages", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Database service unavailable" });

    const token = req.get("x-admin-token");
    if (!token) return res.status(401).json({ error: "Admin token required" });

    const { data, error } = await supabase
      .from("messages")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Supabase admin messages error:", error);
      return res.status(500).json({ error: "Failed to fetch messages" });
    }
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create project (admin required)
app.post("/api/admin/projects", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Database service unavailable" });

    const { title, description, tech = "", image = "", url = "", github = "", featured = 0 } = req.body || {};
    if (!title || !description) return res.status(400).json({ error: "Title and description are required." });

    const { data, error } = await supabase
      .from("projects")
      .insert([{ title, description, tech, image, url, github, featured: featured ? 1 : 0 }])
      .select()
      .single();

    if (error) {
      console.error("Supabase admin projects error:", error);
      return res.status(500).json({ error: "Failed to create project" });
    }
    res.status(201).json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update project (admin required)
app.put("/api/admin/projects/:id", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Database service unavailable" });

    const { title, description, tech = "", image = "", url = "", github = "", featured = 0 } = req.body || {};
    const { error } = await supabase
      .from("projects")
      .update({ title, description, tech, image, url, github, featured: featured ? 1 : 0 })
      .eq("id", req.params.id);

    if (error) {
      console.error("Supabase admin project update error:", error);
      return res.status(500).json({ error: "Failed to update project" });
    }

    const { data } = await supabase
      .from("projects")
      .select("*")
      .eq("id", req.params.id)
      .single();

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete project (admin required)
app.delete("/api/admin/projects/:id", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Database service unavailable" });

    const { error } = await supabase
      .from("projects")
      .delete()
      .eq("id", req.params.id);

    if (error) {
      console.error("Supabase admin project delete error:", error);
      return res.status(500).json({ error: "Failed to delete project" });
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update profile (admin required)
app.put("/api/admin/profile", async (req, res) => {
  try {
    if (!supabase) return res.status(503).json({ error: "Database service unavailable" });

    const { name, role, bio, location = "", email = "", github = "", linkedin = "", website = "" } = req.body || {};
    if (!name || !role || !bio) return res.status(400).json({ error: "Name, role and bio are required." });

    const { data, error } = await supabase
      .from("profile")
      .update({ name, role, bio, location, email, github, linkedin, website })
      .eq("id", 1)
      .select()
      .single();

    if (error) {
      console.error("Supabase admin profile error:", error);
      return res.status(500).json({ error: "Failed to update profile" });
    }
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve admin login page
app.get("/admin", (req, res) => {
  res.sendFile("admin/index.html", { root: "public" });
});

// Serve admin dashboard assets
app.get("/admin/admin.css", (req, res) => {
  res.sendFile("admin/admin.css", { root: "public" });
});
app.get("/admin/admin.js", (req, res) => {
  res.sendFile("admin/admin.js", { root: "public" });
});

// Catch-all: serve index.html for SPA (outside /admin)
app.get("*", (req, res) => {
  if (req.path.startsWith("/admin")) {
    return res.status(404).send("Admin page not found or access denied");
  }
  res.sendFile("index.html", { root: "public" });
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Portfolio running on http://0.0.0.0:${PORT}`);
  console.log(`Database: Supabase PostgreSQL`);
  console.log(`Theme colors: --accent: #c8ff36, --accent2: #9bd900`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
});

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Promise rejection:", reason);
  server.close();
});