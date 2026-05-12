const crypto = require("crypto");

const SESSIONS = {};

// Session expiration: 1 hour
const SESSION_TTL_MS = 60 * 60 * 1000;

function corsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Content-Type", "application/json");
}

// Generate a secure session token
function generateSessionToken(username, ip) {
  const timestamp = Date.now();
  const randomBytes = crypto.randomBytes(32).toString('hex');
  const data = `${username}|${ip}|${timestamp}|${randomBytes}`;
  const hash = crypto.createHash('sha256').update(data).digest('hex');
  return hash;
}

// Clean up expired sessions periodically
function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [token, session] of Object.entries(SESSIONS)) {
    if (session.expiresAt < now) {
      delete SESSIONS[token];
    }
  }
}

// Run cleanup every hour
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

module.exports = async function handler(req, res) {
  corsHeaders(res);

  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Get token from Authorization header
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.substring(7) : null;

  if (!token) {
    return res.status(401).json({
      valid: false,
      error: "No token provided"
    });
  }

  // Check if session exists and is valid
  const session = SESSIONS[token];
  const now = Date.now();

  if (!session) {
    return res.status(401).json({
      valid: false,
      error: "Invalid or expired session"
    });
  }

  if (session.expiresAt < now) {
    delete SESSIONS[token];
    return res.status(401).json({
      valid: false,
      error: "Session expired"
    });
  }

  // Get client IP for additional validation (optional security)
  const clientIP = getClientIP(req);
  
  // Optional: Validate IP hasn't changed (good for security, bad for mobile users)
  // Uncomment if you want strict IP binding
  // if (session.ip !== clientIP) {
  //   delete SESSIONS[token];
  //   return res.status(401).json({
  //     valid: false,
  //     error: "Session IP mismatch"
  //   });
  // }

  // Session is valid - refresh expiry
  session.expiresAt = now + SESSION_TTL_MS;
  
  console.log(`Session validated for user: ${session.username} from IP: ${clientIP}`);

  return res.status(200).json({
    valid: true,
    user: session.username,
    expiresAt: session.expiresAt
  });
};

function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

// Export the SESSIONS object for use in login.js
// This allows both endpoints to share the same session store
module.exports.SESSIONS = SESSIONS;
