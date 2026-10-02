import { createClient } from "npm:@supabase/supabase-js@2";

const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
const serverKey = Deno.env.get("PORTFOLIO_DB_SECRET_KEY") || Deno.env.get("SUPABASE_SECRET_KEY") || Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
const clientKey = serverKey || Deno.env.get("SUPABASE_ANON_KEY") || "";
const adminToken = Deno.env.get("PORTFOLIO_ADMIN_TOKEN") || Deno.env.get("ADMIN_TOKEN") || "";
const supabase = supabaseUrl && clientKey
  ? createClient(supabaseUrl, clientKey, { auth: { persistSession: false, autoRefreshToken: false } })
  : null;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info, x-admin-token",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
};

const defaultProfile = {
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

function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders
    }
  });
}

async function bodyJson(request: Request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function getProfile() {
  const { data, error } = await supabase!.from("profile").select("*").eq("id", 1).maybeSingle();
  if (error) throw error;
  return data || defaultProfile;
}

async function getProjects() {
  const { data, error } = await supabase!.from("projects").select("*").order("created_at", { ascending: false });
  if (error) throw error;
  return data || [];
}

async function getMessages() {
  const { data, error } = await supabase!.from("messages").select("*").order("created_at", { ascending: false });
  if (error) throw error;
  return data || [];
}

async function getVisits() {
  const { data, error } = await supabase!.from("visits")
    .select("id, path, referrer_host, country_code, browser, browser_version, operating_system, device_type, cpu_bucket, memory_bucket, touch_capable, network_type, data_saver, screen_bucket, pixel_ratio_bucket, color_depth_bucket, language, timezone, consent_version, created_at")
    .order("created_at", { ascending: false })
    .limit(100);
  if (error?.code === "PGRST205" || error?.code === "42P01") return [];
  if (error) throw error;
  return data || [];
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const url = new URL(request.url);
  const path = url.searchParams.get("path") || "/api/site-data";
  const method = request.method;

  if (!supabase) return json({ error: "Supabase function secrets are not configured" }, 503);

  if (path.startsWith("/api/admin/")) {
    if (!adminToken) return json({ error: "Admin token is not configured for this function" }, 503);
    if (request.headers.get("x-admin-token") !== adminToken) {
      return json({ error: "Admin token required" }, 401);
    }
    if (!serverKey) return json({ error: "Admin storage requires a server-side Supabase secret key" }, 503);
  }

  try {
    if (method === "GET" && path === "/api/site-data") {
      const [profile, projects] = await Promise.all([getProfile(), getProjects()]);
      return json({ profile, projects });
    }

    if (method === "GET" && path === "/api/profile") {
      return json(await getProfile());
    }

    if (method === "GET" && path === "/api/projects") {
      return json(await getProjects());
    }

    const projectPath = path.match(/^\/api\/projects\/(\d+)$/);
    if (method === "GET" && projectPath) {
      const { data, error } = await supabase.from("projects").select("*").eq("id", projectPath[1]).maybeSingle();
      if (error) return json({ error: error.message }, 500);
      if (!data) return json({ error: "Project not found" }, 404);
      return json(data);
    }

    if (method === "POST" && path === "/api/contact") {
      if (!serverKey) return json({ error: "Contact storage requires a server-side Supabase secret key" }, 503);
      const body = await bodyJson(request);
      if (!body?.name || !body?.email || !body?.message) {
        return json({ error: "Name, email and message are required" }, 400);
      }
      const { data, error } = await supabase.from("messages").insert([{
        name: String(body.name).trim(),
        email: String(body.email).trim(),
        message: String(body.message).trim()
      }]).select().single();
      if (error) return json({ error: error.message }, 500);
      return json(data, 201);
    }

    if (method === "POST" && path === "/api/analytics/visit") {
      const body = await bodyJson(request);
      const pagePath = typeof body?.path === "string" ? body.path : "";
      const referrerHost = typeof body?.referrerHost === "string" ? body.referrerHost : "";
      const browser = typeof body?.browser === "string" ? body.browser : "";
      const browserVersion = typeof body?.browserVersion === "string" ? body.browserVersion : "";
      const operatingSystem = typeof body?.operatingSystem === "string" ? body.operatingSystem : "";
      const deviceType = typeof body?.deviceType === "string" ? body.deviceType : "";
      const cpuBucket = typeof body?.cpuBucket === "string" ? body.cpuBucket : "";
      const memoryBucket = typeof body?.memoryBucket === "string" ? body.memoryBucket : "";
      const touchCapable = body?.touchCapable;
      const networkType = typeof body?.networkType === "string" ? body.networkType : "";
      const dataSaver = body?.dataSaver;
      const screenBucket = typeof body?.screenBucket === "string" ? body.screenBucket : "";
      const pixelRatioBucket = typeof body?.pixelRatioBucket === "string" ? body.pixelRatioBucket : "";
      const colorDepthBucket = typeof body?.colorDepthBucket === "string" ? body.colorDepthBucket : "";
      const language = typeof body?.language === "string" ? body.language : "";
      const timezone = typeof body?.timezone === "string" ? body.timezone : "";
      const countryHeader = request.headers.get("cf-ipcountry") || request.headers.get("x-vercel-ip-country") || "";
      const countryCode = /^[a-z]{2}$/i.test(countryHeader) ? countryHeader.toUpperCase() : "";
      const allowed = {
        browser: ["Chrome", "Firefox", "Safari", "Edge", "Other"],
        operatingSystem: ["Windows", "macOS", "Linux", "ChromeOS", "iOS", "Android", "Other"],
        deviceType: ["Desktop", "Mobile", "Tablet"],
        cpuBucket: ["1-2", "3-4", "5-8", "9+", "unknown"],
        memoryBucket: ["2GB or less", "4GB", "8GB", "16GB+", "unknown"],
        networkType: ["slow-2g", "2g", "3g", "4g", "unknown"],
        screenBucket: ["compact", "standard", "large", "unknown"],
        pixelRatioBucket: ["1x", "2x", "3x+", "unknown"],
        colorDepthBucket: ["24-bit or less", "30-bit+", "unknown"]
      };
      if (body?.consentVersion !== "2026-10-02-v3" || !pagePath.startsWith("/") ||
          pagePath.length > 200 || /[?#]/.test(pagePath) || referrerHost.length > 253 ||
          (referrerHost && !/^[a-z0-9.-]+$/i.test(referrerHost)) ||
          !allowed.browser.includes(browser) || !/^\d{0,3}$/.test(browserVersion) ||
          !allowed.operatingSystem.includes(operatingSystem) || !allowed.deviceType.includes(deviceType) ||
          !allowed.cpuBucket.includes(cpuBucket) || !allowed.memoryBucket.includes(memoryBucket) ||
          typeof touchCapable !== "boolean" || !allowed.networkType.includes(networkType) ||
          typeof dataSaver !== "boolean" || !allowed.screenBucket.includes(screenBucket) ||
          !allowed.pixelRatioBucket.includes(pixelRatioBucket) || !allowed.colorDepthBucket.includes(colorDepthBucket) ||
          language.length > 20 ||
          (language && !/^[a-z0-9-]+$/i.test(language)) || timezone.length > 64 ||
          (timezone && !/^[a-z0-9_+-]+(?:\/[a-z0-9_+-]+)*$/i.test(timezone))) {
        return json({ error: "Invalid consented page view" }, 400);
      }
      const { error } = await supabase.from("visits").insert([{
        path: pagePath,
        referrer_host: referrerHost.toLowerCase(),
        country_code: countryCode,
        browser,
        browser_version: browserVersion,
        operating_system: operatingSystem,
        device_type: deviceType,
        cpu_bucket: cpuBucket,
        memory_bucket: memoryBucket,
        touch_capable: touchCapable,
        network_type: networkType,
        data_saver: dataSaver,
        screen_bucket: screenBucket,
        pixel_ratio_bucket: pixelRatioBucket,
        color_depth_bucket: colorDepthBucket,
        language,
        timezone,
        consent_version: body.consentVersion
      }]);
      if (error) return json({ error: error.message }, 500);
      return json({ accepted: true }, 202);
    }

    if (method === "GET" && path === "/api/admin/dashboard") {
      const [projects, messages, profile, visits] = await Promise.all([getProjects(), getMessages(), getProfile(), getVisits()]);
      return json({ projects, messages, profile, visits });
    }

    const adminVisitPath = path.match(/^\/api\/admin\/visits\/(\d+)$/);
    if (adminVisitPath && method === "DELETE") {
      const { error } = await supabase.from("visits").delete().eq("id", adminVisitPath[1]);
      if (error) return json({ error: error.message }, 500);
      return json({ success: true });
    }

    if (method === "GET" && path === "/api/admin/messages") {
      return json(await getMessages());
    }

    const adminMessagePath = path.match(/^\/api\/admin\/messages\/(\d+)$/);
    if (adminMessagePath && method === "PUT") {
      const body = await bodyJson(request);
      const name = String(body?.name || "").trim();
      const email = String(body?.email || "").trim();
      const message = String(body?.message || "").trim();
      if (!name || !email || !message) return json({ error: "Name, email and message required" }, 400);
      const { data, error } = await supabase.from("messages").update({ name, email, message })
        .eq("id", adminMessagePath[1])
        .select("id, name, email, message, created_at")
        .maybeSingle();
      if (error) return json({ error: error.message }, 500);
      if (!data) return json({ error: "Message not found" }, 404);
      return json(data);
    }

    if (adminMessagePath && method === "DELETE") {
      const { error } = await supabase.from("messages").delete().eq("id", adminMessagePath[1]);
      if (error) return json({ error: error.message }, 500);
      return json({ success: true });
    }

    if (method === "POST" && path === "/api/admin/projects") {
      const body = await bodyJson(request);
      if (!body?.title || !body?.description) return json({ error: "Title and description required" }, 400);
      const { data, error } = await supabase.from("projects").insert([{
        title: String(body.title).trim(),
        description: String(body.description).trim(),
        tech: String(body.tech || ""),
        image: String(body.image || ""),
        url: String(body.url || ""),
        github: String(body.github || ""),
        featured: body.featured ? 1 : 0
      }]).select().single();
      if (error) return json({ error: error.message }, 500);
      return json(data, 201);
    }

    if (method === "PUT" && path === "/api/admin/profile") {
      const body = await bodyJson(request);
      if (!body?.name || !body?.role || !body?.bio) {
        return json({ error: "Name, role and bio required" }, 400);
      }
      const { data, error } = await supabase.from("profile").upsert({
        id: 1,
        name: String(body.name).trim(),
        role: String(body.role).trim(),
        bio: String(body.bio).trim(),
        location: String(body.location || ""),
        email: String(body.email || ""),
        github: String(body.github || ""),
        linkedin: String(body.linkedin || ""),
        website: String(body.website || "")
      }, { onConflict: "id" }).select().single();
      if (error) return json({ error: error.message }, 500);
      return json(data);
    }

    const adminProjectPath = path.match(/^\/api\/admin\/projects\/(\d+)$/);
    if (adminProjectPath && method === "PUT") {
      const body = await bodyJson(request);
      if (!body?.title || !body?.description) return json({ error: "Title and description required" }, 400);
      const { data, error } = await supabase.from("projects").update({
        title: String(body.title).trim(),
        description: String(body.description).trim(),
        tech: String(body.tech || ""),
        image: String(body.image || ""),
        url: String(body.url || ""),
        github: String(body.github || ""),
        featured: body.featured ? 1 : 0
      }).eq("id", adminProjectPath[1]).select().maybeSingle();
      if (error) return json({ error: error.message }, 500);
      if (!data) return json({ error: "Project not found" }, 404);
      return json(data);
    }

    if (adminProjectPath && method === "DELETE") {
      const { error } = await supabase.from("projects").delete().eq("id", adminProjectPath[1]);
      if (error) return json({ error: error.message }, 500);
      return json({ success: true });
    }

    return json({ error: "API endpoint not found" }, 404);
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "Supabase request failed" }, 500);
  }
});