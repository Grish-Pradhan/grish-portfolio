// api/verify-session.js
// Vercel Serverless Function for Session Token Verification
// 
// SETUP INSTRUCTIONS:
// 1. Place this file at: /api/verify-session.js (in your project root)
// 2. Uses SESSION_SECRET environment variable (same as login.js)
// 3. Deploy to Vercel
// 4. Test at: https://your-project.vercel.app/api/verify-session

const crypto = require("crypto");

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

  // Parse request body
  const body = req.body || {};
  const { token } = body;

  if (!token) {
    return res.status(401).json({ valid: false, error: "No token provided" });
  }

  const secret = process.env.SESSION_SECRET || "fallback-secret-change-me";

  try {
    // Split token into data and signature
    const parts = token.split(".");
    if (parts.length !== 2) {
      throw new Error("Malformed token");
    }

    const [datab64, sig] = parts;
    if (!datab64 || !sig) {
      throw new Error("Malformed token");
    }

    // Decode the payload
    const data = Buffer.from(datab64, "base64").toString("utf8");
    
    // Calculate expected signature
    const expectedSig = crypto
      .createHmac("sha256", secret)
      .update(data)
      .digest("hex");

    // Constant-time comparison - FIXED VERSION
    // Both strings should be hex, so they're already the same length
    if (sig.length !== expectedSig.length) {
      throw new Error("Invalid signature");
    }

    const sigBuf = Buffer.from(sig, "utf8");
    const expBuf = Buffer.from(expectedSig, "utf8");

    if (!crypto.timingSafeEqual(sigBuf, expBuf)) {
      throw new Error("Invalid signature");
    }

    // Parse and validate payload
    const payload = JSON.parse(data);
    
    // Check expiration
    if (!payload.exp || Date.now() > payload.exp) {
      console.log("Token expired for user:", payload.user);
      return res.status(401).json({ valid: false, error: "Session expired" });
    }

    // Token is valid
    console.log("Valid session verified for user:", payload.user);
    return res.status(200).json({ 
      valid: true, 
      user: payload.user,
      expiresAt: payload.exp
    });

  } catch (error) {
    console.error("Token verification failed:", error.message);
    return res.status(401).json({ valid: false, error: "Invalid token" });
  }
};