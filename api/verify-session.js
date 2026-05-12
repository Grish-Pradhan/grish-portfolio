const jwt = require('jsonwebtoken');

function corsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Content-Type", "application/json");
}

function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    "unknown"
  );
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

  // Get token from Authorization header
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.substring(7) : null;

  if (!token) {
    return res.status(401).json({
      valid: false,
      error: "No token provided"
    });
  }

  // Check if JWT_SECRET is configured
  if (!process.env.JWT_SECRET) {
    console.error("JWT_SECRET environment variable not set!");
    return res.status(500).json({
      valid: false,
      error: "Server misconfigured"
    });
  }

  // ========== JWT TOKEN VERIFICATION ==========
  try {
    // Verify the JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Optional: Verify IP hasn't changed (adds extra security)
    const clientIP = getClientIP(req);
    // Uncomment the line below if you want to bind sessions to IP addresses
    // if (decoded.ip !== clientIP) {
    //   return res.status(401).json({ valid: false, error: "IP address mismatch" });
    // }
    
    console.log(`Session validated for user: ${decoded.username} from IP: ${clientIP}`);
    
    // Return success with user info
    return res.status(200).json({ 
      valid: true, 
      user: decoded.username,
      expiresAt: decoded.exp * 1000 // Convert to milliseconds
    });
    
  } catch (error) {
    // Token is invalid or expired
    console.error("JWT verification failed:", error.message);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        valid: false, 
        error: "Token expired" 
      });
    }
    
    return res.status(401).json({ 
      valid: false, 
      error: "Invalid token" 
    });
  }
};
