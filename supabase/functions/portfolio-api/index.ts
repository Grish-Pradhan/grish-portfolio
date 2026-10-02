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

    if (method === "GET" && path === "/api/admin/dashboard") {
      const [projects, messages, profile] = await Promise.all([getProjects(), getMessages(), getProfile()]);
      return json({ projects, messages, profile });
    }

    if (method === "GET" && path === "/api/admin/messages") {
      return json(await getMessages());
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