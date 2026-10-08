// Local-only, read-only fixture server for dashboard visual QA. No real admin token required.
// Run from the repository root: node scripts/preview-admin-ui.mjs
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { resolve } from "node:path";

const profile = { name:"Grish Pradhan", role:"Security & software", location:"Lalitpur, Nepal", bio:"Local preview content." };
const projects = [{ id:1, title:"Security toolkit", description:"Sample project for local layout testing.", tech:"Python, React", featured:true }];
const certifications = [
  { id:7, title:"APISEC Certified Practitioner", issuer:"APISEC University", issued_on:"2026-03-25", image_url:"/certificates/ACP.png" },
  { id:14, title:"Certified API Security Analyst", issuer:"APISEC University", issued_on:"2026-03-14", image_url:"/certificates/casa-grish.png" },
  { id:10, title:"Certified Threat Intelligence & Governance Analyst", issuer:"Red Team Leaders", issued_on:"2026-01-11", image_url:"/certificates/CTIGA.jpg" }
];
const visits = Array.from({ length:24 }, (_, i) => ({ id:i + 1, path:i % 2 ? "/portfolio" : "/world", browser:["Chrome","Chrome","Firefox","Safari"][i % 4], operating_system:["Windows","macOS","Android"][i % 3], device_type:i % 3 ? "Desktop" : "Mobile", country_code:"NP", created_at:"2026-10-08T10:00:00Z" }));
const data = { profile, projects, certifications, visits, messages:[{ id:1, name:"Preview visitor", email:"preview@example.com", message:"Local sample message. No production inbox is used.", created_at:"2026-10-08T10:00:00Z" }] };
const api = createServer((request, response) => {
  response.setHeader("Content-Type", "application/json");
  response.setHeader("Cache-Control", "no-store");
  if (request.method !== "GET") { response.writeHead(405); response.end(JSON.stringify({ error:"Preview is read-only" })); return; }
  if (request.url === "/api/admin/dashboard") {
    if (request.headers["x-admin-token"] !== "preview-only") { response.writeHead(401); response.end(JSON.stringify({ error:"Admin token required" })); return; }
    response.end(JSON.stringify(data)); return;
  }
  if (request.url === "/api/site-data") { response.end(JSON.stringify({ profile, projects, certifications })); return; }
  response.writeHead(404); response.end(JSON.stringify({ error:"Not part of the preview" }));
});
api.listen(3000, "127.0.0.1", () => {
  const child = spawn(process.execPath, [resolve("node_modules/vite/bin/vite.js"), "--host", "127.0.0.1", "--port", "5173", "--strictPort"], { stdio:"inherit" });
  console.log("LOCAL FIXTURES ONLY. Admin preview token: preview-only");
  const stop = () => { child.kill(); api.close(); };
  process.on("SIGINT", stop); process.on("SIGTERM", stop);
  child.on("exit", () => api.close());
});
