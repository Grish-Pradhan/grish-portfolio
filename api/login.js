// api/login.js
// Simple Authentication - Username & Password Only (No Tokens)
// 
// SETUP INSTRUCTIONS:
// 1. Place this file at: /api/login.js
// 2. Set Environment Variables in Vercel:
//    - ADMIN_USERNAME (e.g., "grish")
//    - ADMIN_PASSWORD (your secure password)
// 3. Deploy to Vercel

const crypto = require("crypto");

// In-memory rate limiting
const RATE_LIMIT = {};
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 30 * 1000; // 30 seconds

function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

function corsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Content-Type", "application/json");
}

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

  // Initialize rate limiting
  if (!RATE_LIMIT[ip]) {
    RATE_LIMIT[ip] = { attempts: 0, lockedUntil: 0 };
  }
  const record = RATE_LIMIT[ip];

  // Check if locked out
  if (record.lockedUntil > now) {
    const remaining = Math.ceil((record.lockedUntil - now) / 1000);
    return res.status(429).json({
      success: false,
      error: `Too many attempts. Try again in ${remaining}s.`,
      lockedFor: remaining,
    });
  }

  // Parse request body
  const body = req.body || {};
  const { username, password } = body;

  // Get credentials from environment
  const validUser = process.env.ADMIN_USERNAME || "grish";
  const validPass = process.env.ADMIN_PASSWORD;

  // Check if password is configured
  if (!validPass) {
    console.error("ADMIN_PASSWORD environment variable not set!");
    return res.status(500).json({
      success: false,
      error: "Server misconfigured",
    });
  }

  // Validate input
  if (!username || !password) {
    record.attempts++;
    return res.status(400).json({
      success: false,
      error: "Username and password are required",
      attemptsLeft: MAX_ATTEMPTS - record.attempts,
    });
  }

  // Constant-time comparison to prevent timing attacks
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

  // Handle failed login
  if (!userMatch || !passMatch) {
    record.attempts++;

    if (record.attempts >= MAX_ATTEMPTS) {
      record.lockedUntil = now + LOCKOUT_MS;
      record.attempts = 0;
      console.log(`IP ${ip} locked out for 30 seconds`);
      return res.status(429).json({
        success: false,
        error: "Too many failed attempts. Locked for 30 seconds.",
        lockedFor: 30,
      });
    }

    console.log(`Failed login from ${ip}. Attempts: ${record.attempts}`);
    return res.status(401).json({
      success: false,
      error: "Invalid credentials",
      attemptsLeft: MAX_ATTEMPTS - record.attempts,
    });
  }

  // Success - reset attempts
  record.attempts = 0;
  record.lockedUntil = 0;

  console.log(`Successful login from ${ip} for user: ${validUser}`);
  
  // Return success without token
  return res.status(200).json({
    success: true,
    message: "Login successful",
    user: validUser,
  });
};
