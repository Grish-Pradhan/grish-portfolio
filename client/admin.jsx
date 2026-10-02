import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

async function api(path, token, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("x-admin-token", token);
  const response = await window.portfolioApi(path, { ...options, headers });
  let data = {};
  try {
    data = await response.json();
  } catch {
    throw new Error(`Unexpected response (${response.status})`);
  }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

const emptyProject = () => ({ id: "", title: "", description: "", tech: "", image: "", url: "", github: "", featured: false });
const emptyMessage = () => ({ id: "", name: "", email: "", message: "" });
const profileFields = ["name", "role", "bio", "location", "email", "github", "linkedin", "website"];

function AdminApp() {
  const [token, setToken] = useState(sessionStorage.getItem("adminToken") || "");
  const [loginToken, setLoginToken] = useState("");
  const [authenticated, setAuthenticated] = useState(false);
  const [activeSection, setActiveSection] = useState("dashboard");
  const [projects, setProjects] = useState([]);
  const [messages, setMessages] = useState([]);
  const [visits, setVisits] = useState([]);
  const [profile, setProfile] = useState({ name: "", role: "", bio: "", location: "", email: "", github: "", linkedin: "", website: "" });
  const [profileDirty, setProfileDirty] = useState(false);
  const [profileStatus, setProfileStatus] = useState("");
  const [loginStatus, setLoginStatus] = useState("");
  const [dashboardError, setDashboardError] = useState("");
  const [projectModalOpen, setProjectModalOpen] = useState(false);
  const [projectDraft, setProjectDraft] = useState(emptyProject);
  const [projectStatus, setProjectStatus] = useState("");
  const [messageModalOpen, setMessageModalOpen] = useState(false);
  const [messageDraft, setMessageDraft] = useState(emptyMessage);
  const [messageStatus, setMessageStatus] = useState("");

  async function refreshDashboard(currentToken = token) {
    const data = await api("/api/admin/dashboard", currentToken);
    setProjects(data.projects || []);
    setMessages(data.messages || []);
    setVisits(data.visits || []);
    if (!profileDirty) setProfile(data.profile || {});
    setDashboardError("");
    setAuthenticated(true);
  }

  useEffect(() => {
    if (!token || !authenticated) return undefined;
    let active = true;
    const refresh = async () => {
      if (!active || document.hidden || profileDirty || projectModalOpen || messageModalOpen) return;
      try {
        await refreshDashboard(token);
      } catch (error) {
        if (error.message === "Admin token required") {
          sessionStorage.removeItem("adminToken");
          setToken("");
          setAuthenticated(false);
        } else if (active) {
          setDashboardError(error.message);
        }
      }
    };
    const timer = window.setInterval(refresh, 30000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      active = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [token, authenticated, profileDirty, projectModalOpen, messageModalOpen]);

  async function submitLogin(event) {
    event.preventDefault();
    setLoginStatus("");
    try {
      const data = await api("/api/admin/dashboard", loginToken);
      sessionStorage.setItem("adminToken", loginToken);
      setToken(loginToken);
      setProjects(data.projects || []);
      setMessages(data.messages || []);
      setVisits(data.visits || []);
      setProfile(data.profile || {});
      setAuthenticated(true);
    } catch (error) {
      setLoginStatus(error.message === "Admin token required" ? "Invalid admin token." : error.message);
    }
  }

  function logout() {
    sessionStorage.removeItem("adminToken");
    setToken("");
    setAuthenticated(false);
  }

  function updateProfile(event) {
    const { name, value } = event.target;
    setProfile((current) => ({ ...current, [name]: value }));
    setProfileDirty(true);
    setProfileStatus("");
  }

  async function saveProfile(event) {
    event.preventDefault();
    try {
      const updated = await api("/api/admin/profile", token, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(profile)
      });
      setProfile(updated);
      setProfileDirty(false);
      setProfileStatus("Saved.");
      await refreshDashboard(token);
    } catch (error) {
      setProfileStatus(error.message);
    }
  }

  function openProject(project = emptyProject()) {
    setProjectDraft({ ...emptyProject(), ...project, featured: Boolean(project.featured) });
    setProjectStatus("");
    setProjectModalOpen(true);
  }

  function updateProject(event) {
    const { name, value, checked, type } = event.target;
    setProjectDraft((current) => ({ ...current, [name]: type === "checkbox" ? checked : value }));
  }

  async function saveProject(event) {
    event.preventDefault();
    const isEdit = Boolean(projectDraft.id);
    const path = `/api/admin/projects${isEdit ? `/${projectDraft.id}` : ""}`;
    const body = { ...projectDraft, featured: projectDraft.featured ? 1 : 0 };
    delete body.id;
    try {
      await api(path, token, {
        method: isEdit ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      setProjectModalOpen(false);
      await refreshDashboard(token);
    } catch (error) {
      setProjectStatus(error.message);
    }
  }

  async function deleteProject(id) {
    if (!window.confirm("Delete this project?")) return;
    try {
      await api(`/api/admin/projects/${id}`, token, { method: "DELETE" });
      await refreshDashboard(token);
    } catch (error) {
      setDashboardError(error.message);
    }
  }

  function openMessage(message) {
    setMessageDraft({ ...message });
    setMessageStatus("");
    setMessageModalOpen(true);
  }

  function updateMessage(event) {
    const { name, value } = event.target;
    setMessageDraft((current) => ({ ...current, [name]: value }));
    setMessageStatus("");
  }

  async function saveMessage(event) {
    event.preventDefault();
    try {
      await api(`/api/admin/messages/${messageDraft.id}`, token, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: messageDraft.name, email: messageDraft.email, message: messageDraft.message })
      });
      setMessageModalOpen(false);
      await refreshDashboard(token);
    } catch (error) {
      setMessageStatus(error.message);
    }
  }

  async function deleteMessage(id) {
    if (!window.confirm("Delete this message?")) return;
    try {
      await api(`/api/admin/messages/${id}`, token, { method: "DELETE" });
      await refreshDashboard(token);
    } catch (error) {
      setDashboardError(error.message);
    }
  }

  useEffect(() => {
    if (!token || authenticated) return;
    let active = true;
    api("/api/admin/dashboard", token)
      .then((data) => {
        if (!active) return;
        setProjects(data.projects || []);
        setMessages(data.messages || []);
        setVisits(data.visits || []);
        setProfile(data.profile || {});
        setAuthenticated(true);
      })
      .catch((error) => {
        if (active && error.message !== "Admin token required") setLoginStatus(error.message);
        if (error.message === "Admin token required") sessionStorage.removeItem("adminToken");
      });
    return () => { active = false; };
  }, [token, authenticated]);

  if (!authenticated) {
    return (
      <div className="login-wrap">
        <div className="login-card">
          <div className="brand">GRISH PORTFOLIO</div>
          <h1>Admin Login</h1>
          <p>Secure dashboard access</p>
          <form onSubmit={submitLogin}>
            <input type="password" value={loginToken} onChange={(event) => setLoginToken(event.target.value)} placeholder="Enter admin token" required />
            <button type="submit" className="button">Login</button>
          </form>
          <div className="status" role="status">{loginStatus}</div>
        </div>
      </div>
    );
  }

  const sections = ["dashboard", "projects", "messages", "visits", "profile"];
  const pageTitles = { dashboard: "Dashboard", projects: "Projects", messages: "Messages", visits: "Visitors", profile: "Profile" };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">◆ GRISH PORTFOLIO</div>
        <nav>
          {sections.map((section) => (
            <button key={section} className={`nav-item ${activeSection === section ? "active" : ""}`} onClick={() => setActiveSection(section)}>
              {pageTitles[section]}
            </button>
          ))}
        </nav>
        <div className="side-bottom"><button type="button" onClick={logout}>Logout</button></div>
      </aside>

      <main className="main">
        <div className="topbar">
          <div><p className="eyebrow">ADMIN DASHBOARD</p><h2>{pageTitles[activeSection]}</h2></div>
          <span className="secure">● Secure</span>
        </div>
        {dashboardError && <p className="status" role="alert">{dashboardError}</p>}

        {activeSection === "dashboard" && (
          <section id="dashboard" className="page active">
            <div className="stats">
              <div className="stat"><small>Total Projects</small><strong>{projects.length}</strong></div>
              <div className="stat"><small>Messages</small><strong>{messages.length}</strong></div>
              <div className="stat"><small>Featured</small><strong>{projects.filter((project) => project.featured).length}</strong></div>
              <div className="stat"><small>Recent Visits</small><strong>{visits.length}</strong></div>
            </div>
            <div className="intro">
              <div><div className="big-mark">◆</div><h3>Portfolio Overview</h3><p>Manage your projects, view visitor messages, and update your profile.</p></div>
              <div><div className="big-mark">◆</div><h3>Quick Stats</h3><p>Portfolio activity refreshes automatically while this tab is open.</p></div>
            </div>
          </section>
        )}

        {activeSection === "projects" && (
          <section id="projects" className="page active">
            <div className="section-title"><h3>Projects Management</h3></div>
            <div className="project-list">
              {projects.length ? projects.map((project) => (
                <article className="project-row" key={project.id}>
                  <div>
                    <h4>{project.title} {project.featured ? <span className="meta"> · FEATURED</span> : null}</h4>
                    <p>{project.description}</p>
                    <span className="meta">{project.tech || ""}</span>
                  </div>
                  <div className="row-actions">
                    <button className="small-btn" onClick={() => openProject(project)}>Edit</button>
                    <button className="small-btn delete" onClick={() => deleteProject(project.id)}>Delete</button>
                  </div>
                </article>
              )) : <div className="panel" style={{ padding: 25, color: "#969ba7" }}>No projects yet.</div>}
            </div>
            <button type="button" className="button primary" style={{ marginTop: 20, width: "100%" }} onClick={() => openProject()}>Add New Project</button>
          </section>
        )}

        {activeSection === "messages" && (
          <section id="messages" className="page active">
            <div className="section-title"><h3>Contact Messages</h3></div>
            <div className="messages">
              {messages.length ? messages.map((message) => (
                <article className="message" key={message.id}>
                  <div><h4>{message.name}</h4><p>{message.message}</p></div>
                  <div className="meta">{message.email} · {message.created_at}</div>
                  <div className="row-actions">
                    <button className="small-btn" onClick={() => openMessage(message)}>Edit</button>
                    <button className="small-btn delete" onClick={() => deleteMessage(message.id)}>Delete</button>
                  </div>
                </article>
              )) : <div className="panel" style={{ padding: 25, color: "#969ba7" }}>No messages yet.</div>}
            </div>
          </section>
        )}

        {activeSection === "visits" && (
          <section id="visits" className="page active">
            <div className="section-title"><h3>Recent Consented Visits</h3></div>
            <div className="messages">
              {visits.length ? visits.map((visit) => (
                <article className="message visit-row" key={visit.id}>
                  <div><h4>{visit.path}</h4><p>{visit.referrer_host || "Direct visit"}</p></div>
                  <div className="visit-facts">
                    <span>{visit.country_code || "Country unavailable"}</span>
                    <span>{visit.browser || "Browser unavailable"}</span>
                    <span>{visit.language || "Language unavailable"}</span>
                    <span>{visit.timezone || "Timezone unavailable"}</span>
                  </div>
                  <time className="visit-time" dateTime={visit.created_at}>{new Date(visit.created_at).toLocaleString()}</time>
                </article>
              )) : <div className="panel" style={{ padding: 25, color: "#969ba7" }}>No consented visits recorded yet.</div>}
            </div>
          </section>
        )}

        {activeSection === "profile" && (
          <section id="profile" className="page active">
            <div className="section-title"><h3>Profile Editing</h3></div>
            <div className="intro">
              <div className="big-mark">◆</div>
              <div>
                <h3>Update Profile</h3>
                <p>Modify your public profile information.</p>
              </div>
              <form id="profileForm" onSubmit={saveProfile} onChange={updateProfile}>
                <input type="hidden" name="id" value="1" readOnly />
                {profileFields.map((field) => field === "bio" ? (
                  <textarea key={field} id="profileBio" name={field} value={profile[field] || ""} onChange={updateProfile} placeholder="Bio" required rows="4" />
                ) : (
                  <input key={field} name={field} type={field === "email" ? "email" : ["github", "linkedin", "website"].includes(field) ? "url" : "text"} value={profile[field] || ""} onChange={updateProfile} placeholder={field[0].toUpperCase() + field.slice(1)} required={["name", "role"].includes(field)} />
                ))}
                <button type="submit" className="button primary">Save Changes</button>
                <p className="status" role="status">{profileStatus}</p>
              </form>
            </div>
          </section>
        )}
      </main>

      {projectModalOpen && (
        <div className="modal" role="dialog" aria-modal="true" aria-labelledby="modalTitle" onMouseDown={(event) => { if (event.target === event.currentTarget) setProjectModalOpen(false); }}>
          <section className="modal-panel">
            <div className="modal-head">
              <div><p className="eyebrow">PROJECT EDITOR</p><h3 id="modalTitle">{projectDraft.id ? "Edit project" : "New project"}</h3></div>
              <button className="modal-close" type="button" aria-label="Close project editor" onClick={() => setProjectModalOpen(false)}>×</button>
            </div>
            <form id="projectForm" onSubmit={saveProject}>
              <label>Title<input name="title" value={projectDraft.title} onChange={updateProject} required /></label>
              <label className="modal-full">Description<textarea name="description" value={projectDraft.description} onChange={updateProject} rows="4" required /></label>
              <label>Technologies<input name="tech" value={projectDraft.tech} onChange={updateProject} placeholder="JavaScript, Node.js" /></label>
              <label>Image URL<input name="image" type="url" value={projectDraft.image} onChange={updateProject} /></label>
              <label>Live project URL<input name="url" type="url" value={projectDraft.url} onChange={updateProject} /></label>
              <label>GitHub URL<input name="github" type="url" value={projectDraft.github} onChange={updateProject} /></label>
              <label className="featured-toggle"><input name="featured" type="checkbox" checked={projectDraft.featured} onChange={updateProject} /><span>Featured project</span></label>
              <p className="status modal-full" role="status">{projectStatus}</p>
              <div className="modal-actions modal-full">
                <button className="small-btn" type="button" onClick={() => setProjectModalOpen(false)}>Cancel</button>
                <button className="button primary" type="submit">Save project</button>
              </div>
            </form>
          </section>
        </div>
      )}

      {messageModalOpen && (
        <div className="modal" role="dialog" aria-modal="true" aria-labelledby="messageModalTitle" onMouseDown={(event) => { if (event.target === event.currentTarget) setMessageModalOpen(false); }}>
          <section className="modal-panel">
            <div className="modal-head">
              <div><p className="eyebrow">MESSAGE EDITOR</p><h3 id="messageModalTitle">Edit message</h3></div>
              <button className="modal-close" type="button" aria-label="Close message editor" onClick={() => setMessageModalOpen(false)}>×</button>
            </div>
            <form id="messageForm" onSubmit={saveMessage}>
              <label>Name<input name="name" value={messageDraft.name} onChange={updateMessage} required /></label>
              <label>Email<input name="email" type="email" value={messageDraft.email} onChange={updateMessage} required /></label>
              <label className="modal-full">Message<textarea name="message" value={messageDraft.message} onChange={updateMessage} rows="5" required /></label>
              <p className="status modal-full" role="status">{messageStatus}</p>
              <div className="modal-actions modal-full">
                <button className="small-btn" type="button" onClick={() => setMessageModalOpen(false)}>Cancel</button>
                <button className="button primary" type="submit">Save message</button>
              </div>
            </form>
          </section>
        </div>
      )}
    </div>
  );
}

createRoot(document.getElementById("root")).render(<AdminApp />);