// api/login.js
// Vercel Serverless Function for Authentication
// 
// SETUP INSTRUCTIONS:
// 1. Place this file at: /api/login.js (in your project root)
// 2. Set these Environment Variables in Vercel Dashboard:
//    - ADMIN_USERNAME (your username, e.g., "grish")
//    - ADMIN_PASSWORD (your secure password)
//    - SESSION_SECRET (long random string from .env file)
// 3. Deploy to Vercel
// 4. Test at: https://your-project.vercel.app/api/login

const crypto = require("crypto");

// In-memory rate limiting (resets on new serverless instance)
const RATE_LIMIT = {};
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 30 * 1000; // 30 seconds

/**
 * Get client IP address from request headers
 */
function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

/**
 * Sign token with HMAC-SHA256
 */
function signToken(payload) {
  const secret = process.env.SESSION_SECRET || "fallback-secret-change-me";
  const data = JSON.stringify(payload);
  const sig = crypto.createHmac("sha256", secret).update(data).digest("hex");
  return Buffer.from(data).toString("base64") + "." + sig;
}

/**
 * Set CORS headers for cross-origin requests
 */
function corsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Content-Type", "application/json");
}

/**
 * Main handler function
 */
module.exports = async function handler(req, res) {
  corsHeaders(res);

  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const ip = getClientIP(req);
  const now = Date.now();

  // Initialize rate limiting for this IP
  if (!RATE_LIMIT[ip]) {
    RATE_LIMIT[ip] = { attempts: 0, lockedUntil: 0 };
  }
  const record = RATE_LIMIT[ip];

  // Check if IP is currently locked out
  if (record.lockedUntil > now) {
    const remaining = Math.ceil((record.lockedUntil - now) / 1000);
    return res.status(429).json({
      error: `Too many attempts. Try again in ${remaining}s.`,
      lockedFor: remaining,
    });
  }

  // Parse request body
  const body = req.body || {};
  const { username, password } = body;

  // Get credentials from environment variables
  const validUser = process.env.ADMIN_USERNAME || "grish";
  const validPass = process.env.ADMIN_PASSWORD;

  // Verify environment is configured
  if (!validPass) {
    console.error("ADMIN_PASSWORD environment variable not set!");
    return res.status(500).json({
      error: "Server misconfigured: ADMIN_PASSWORD env var not set.",
    });
  }

  // Ensure input exists
  if (!username || !password) {
    record.attempts++;
    return res.status(400).json({
      error: "Username and password are required",
      attemptsLeft: MAX_ATTEMPTS - record.attempts,
    });
  }

  // Constant-time comparison to prevent timing attacks
  // Pad buffers to same length
  const maxUserLen = Math.max(username.length, validUser.length);
  const maxPassLen = Math.max(password.length, validPass.length);

  const userBuf = Buffer.alloc(maxUserLen);
  const validUserBuf = Buffer.alloc(maxUserLen);
  Buffer.from(username).copy(userBuf);
  Buffer.from(validUser).copy(validUserBuf);

  const passBuf = Buffer.alloc(maxPassLen);
  const validPassBuf = Buffer.alloc(maxPassLen);
  Buffer.from(password).copy(passBuf);
  Buffer.from(validPass).copy(validPassBuf);

  const userMatch = crypto.timingSafeEqual(userBuf, validUserBuf);
  const passMatch = crypto.timingSafeEqual(passBuf, validPassBuf);

  // Handle failed authentication
  if (!userMatch || !passMatch) {
    record.attempts++;
    
    // Lock out after max attempts
    if (record.attempts >= MAX_ATTEMPTS) {
      record.lockedUntil = now + LOCKOUT_MS;
      record.attempts = 0;
      console.log(`IP ${ip} locked out for 30 seconds`);
      return res.status(429).json({
        error: "Too many failed attempts. Locked for 30 seconds.",
        lockedFor: 30,
      });
    }

    console.log(`Failed login attempt from ${ip}. Attempts: ${record.attempts}`);
    return res.status(401).json({
      error: "Invalid credentials",
      attemptsLeft: MAX_ATTEMPTS - record.attempts,
    });
  }

  // Success — reset rate limit, issue token
  record.attempts = 0;
  record.lockedUntil = 0;

  const token = signToken({
    user: validUser,
    exp: now + 3600 * 1000, // 1 hour expiry
    iat: now,
  });

  console.log(`Successful login from ${ip} for user: ${validUser}`);
  return res.status(200).json({ success: true, token });
};