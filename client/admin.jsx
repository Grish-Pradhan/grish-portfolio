import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { BarController, BarElement, CategoryScale, Chart, Legend, LinearScale, Tooltip } from "chart.js";

Chart.register(BarController, BarElement, CategoryScale, LinearScale, Tooltip, Legend);
Chart.defaults.color = "#969ba7";

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
const emptyCertification = () => ({ id: "", title: "", issuer: "", issued_on: "", credential_url: "", image_url: "", description: "", imageFile: null, imageName: "" });
const profileFields = ["name", "role", "bio", "location", "email", "github", "linkedin", "website"];
const chartPalette = ["#c8ff36", "#38c9a9", "#5da9ff", "#ffbe55", "#ff7185", "#af91ff", "#55d1db", "#b1bdc9"];

function VisitorChart({ title, field, visits }) {
  const canvasRef = useRef(null);
  const counts = visits.reduce((result, visit) => {
    const value = visit[field];
    const category = value === null || value === undefined || value === "" ? "Unavailable" : String(value);
    result[category] = (result[category] || 0) + 1;
    return result;
  }, {});
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);

  useEffect(() => {
    if (!canvasRef.current || !entries.length) return undefined;
    const chart = new Chart(canvasRef.current, {
      type: "bar",
      data: {
        labels: entries.map(([label]) => label),
        datasets: [{
          data: entries.map(([, count]) => count),
          backgroundColor: entries.map((_, index) => chartPalette[index % chartPalette.length]),
          borderWidth: 0,
          borderRadius: 2
        }]
      },
      options: {
        maintainAspectRatio: false,
        animation: { duration: 180 },
        plugins: {
          legend: { display: false },
          tooltip: { displayColors: false }
        },
        scales: {
          x: { grid: { display: false }, ticks: { color: "#969ba7", maxRotation: 35, minRotation: 0 } },
          y: { beginAtZero: true, ticks: { precision: 0, stepSize: 1, color: "#969ba7" }, grid: { color: "rgba(150,155,167,.12)" } }
        }
      }
    });
    return () => chart.destroy();
  }, [field, entries, title]);

  return (
    <article className="analytics-card">
      <h4>{title}</h4>
      {entries.length
        ? <div className="analytics-canvas"><canvas ref={canvasRef} role="img" aria-label={`${title} visitor distribution`} /></div>
        : <p className="analytics-empty">No consented visits yet.</p>}
    </article>
  );
}

function AdminApp() {
  const [token, setToken] = useState(sessionStorage.getItem("adminToken") || "");
  const [loginToken, setLoginToken] = useState("");
  const [authenticated, setAuthenticated] = useState(false);
  const [activeSection, setActiveSection] = useState("dashboard");
  const [projects, setProjects] = useState([]);
  const [messages, setMessages] = useState([]);
  const [visits, setVisits] = useState([]);
  const [certifications, setCertifications] = useState([]);
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
  const [certificationModalOpen, setCertificationModalOpen] = useState(false);
  const [certificationDraft, setCertificationDraft] = useState(emptyCertification);
  const [certificationStatus, setCertificationStatus] = useState("");

  async function refreshDashboard(currentToken = token) {
    const data = await api("/api/admin/dashboard", currentToken);
    setProjects(data.projects || []);
    setMessages(data.messages || []);
    setVisits(data.visits || []);
    setCertifications(data.certifications || []);
    if (!profileDirty) setProfile(data.profile || {});
    setDashboardError("");
    setAuthenticated(true);
  }

  useEffect(() => {
    if (!token || !authenticated) return undefined;
    let active = true;
    const refresh = async () => {
      if (!active || document.hidden || profileDirty || projectModalOpen || messageModalOpen || certificationModalOpen) return;
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
  }, [token, authenticated, profileDirty, projectModalOpen, messageModalOpen, certificationModalOpen]);

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
      setCertifications(data.certifications || []);
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

  function openCertification(certification = emptyCertification()) {
    setCertificationDraft({ ...emptyCertification(), ...certification, imageFile: null, imageName: "" });
    setCertificationStatus("");
    setCertificationModalOpen(true);
  }

  function updateCertification(event) {
    const { name, value, files } = event.target;
    if (name === "imageFile") {
      const file = files?.[0] || null;
      setCertificationDraft((current) => ({ ...current, imageFile: file, imageName: file?.name || "" }));
      return;
    }
    setCertificationDraft((current) => ({ ...current, [name]: value }));
    setCertificationStatus("");
  }

  function fileAsDataUrl(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error("Could not read the certificate image."));
      reader.readAsDataURL(file);
    });
  }

  async function saveCertification(event) {
    event.preventDefault();
    try {
      let imageUrl = certificationDraft.image_url || "";
      if (certificationDraft.imageFile) {
        if (!certificationDraft.imageFile.type.startsWith("image/")) throw new Error("Choose an image file.");
        if (certificationDraft.imageFile.size > 5 * 1024 * 1024) throw new Error("Images must be smaller than 5 MB.");
        const data = await fileAsDataUrl(certificationDraft.imageFile);
        const upload = await api("/api/admin/uploads", token, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ fileName: certificationDraft.imageFile.name, contentType: certificationDraft.imageFile.type, data })
        });
        imageUrl = upload.url;
      }
      const body = { title: certificationDraft.title, issuer: certificationDraft.issuer, issued_on: certificationDraft.issued_on || null, credential_url: certificationDraft.credential_url, image_url: imageUrl, description: certificationDraft.description };
      const isEdit = Boolean(certificationDraft.id);
      await api(`/api/admin/certifications${isEdit ? `/${certificationDraft.id}` : ""}`, token, {
        method: isEdit ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      setCertificationModalOpen(false);
      await refreshDashboard(token);
    } catch (error) { setCertificationStatus(error.message); }
  }

  async function deleteCertification(id) {
    if (!window.confirm("Delete this certification?")) return;
    try {
      await api(`/api/admin/certifications/${id}`, token, { method: "DELETE" });
      await refreshDashboard(token);
    } catch (error) { setDashboardError(error.message); }
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

  async function deleteVisit(id) {
    if (!window.confirm("Delete this visitor record?")) return;
    try {
      await api(`/api/admin/visits/${id}`, token, { method: "DELETE" });
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

  const sections = ["dashboard", "projects", "certifications", "messages", "visits", "profile"];
  const pageTitles = { dashboard: "Dashboard", projects: "Projects", certifications: "Certifications", messages: "Messages", visits: "Visitors", profile: "Profile" };

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
              <div className="stat"><small>Certifications</small><strong>{certifications.length}</strong></div>
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

        {activeSection === "certifications" && (
          <section id="certifications" className="page active">
            <div className="section-title"><div><h3>Certification library</h3><p>Build trust with verifiable credentials and supporting artwork.</p></div></div>
            <div className="certification-admin-grid">
              {certifications.length ? certifications.map((certification) => (
                <article className="certification-admin-card" key={certification.id}>
                  {certification.image_url ? <img src={certification.image_url} alt="" loading="lazy" /> : <div className="certification-placeholder">✦</div>}
                  <div className="certification-admin-copy">
                    <span className="meta">{certification.issued_on || "Credential"}</span>
                    <h4>{certification.title}</h4>
                    <p>{certification.issuer}</p>
                    <div className="row-actions"><button className="small-btn" onClick={() => openCertification(certification)}>Edit</button><button className="small-btn delete" onClick={() => deleteCertification(certification.id)}>Delete</button></div>
                  </div>
                </article>
              )) : <div className="panel" style={{ padding: 25, color: "#91a4ac" }}>No certifications yet.</div>}
            </div>
            <button type="button" className="button primary" style={{ marginTop: 20, width: "100%" }} onClick={() => openCertification()}>Add Certification</button>
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
            <div className="analytics-charts">
              <VisitorChart title="Browser" field="browser" visits={visits} />
              <VisitorChart title="Operating system" field="operating_system" visits={visits} />
              <VisitorChart title="Device type" field="device_type" visits={visits} />
              <VisitorChart title="Network" field="network_type" visits={visits} />
              <VisitorChart title="CPU cores" field="cpu_bucket" visits={visits} />
              <VisitorChart title="Approx. memory" field="memory_bucket" visits={visits} />
              <VisitorChart title="Screen class" field="screen_bucket" visits={visits} />
              <VisitorChart title="Pixel ratio" field="pixel_ratio_bucket" visits={visits} />
              <VisitorChart title="Color depth" field="color_depth_bucket" visits={visits} />
              <VisitorChart title="Country" field="country_code" visits={visits} />
              <VisitorChart title="Language" field="language" visits={visits} />
              <VisitorChart title="Touch capability" field="touch_capable" visits={visits} />
              <VisitorChart title="Data saver" field="data_saver" visits={visits} />
            </div>
            <div className="messages">
              {visits.length ? visits.map((visit) => (
                <article className="message visit-row" key={visit.id}>
                  <div><h4>{visit.path}</h4><p>{visit.referrer_host || "Direct visit"}</p></div>
                  <div className="visit-facts">
                    <span>{visit.country_code || "Country unavailable"}</span>
                    <span>{visit.browser ? `${visit.browser}${visit.browser_version ? ` ${visit.browser_version}` : ""}` : "Browser unavailable"}</span>
                    <span>{visit.operating_system || "OS unavailable"}</span>
                    <span>{visit.device_type || "Device unavailable"}</span>
                    <span>CPU: {visit.cpu_bucket || "unknown"}</span>
                    <span>RAM: {visit.memory_bucket || "unknown"}</span>
                    <span>Network: {visit.network_type || "unknown"}</span>
                    <span>Screen: {visit.screen_bucket || "unknown"}</span>
                    <span>{visit.language || "Language unavailable"}</span>
                    <span>{visit.timezone || "Timezone unavailable"}</span>
                    {visit.touch_capable && <span>Touch enabled</span>}
                    {visit.data_saver && <span>Data saver</span>}
                  </div>
                  <time className="visit-time" dateTime={visit.created_at}>{new Date(visit.created_at).toLocaleString()}</time>
                  <div className="row-actions"><button className="small-btn delete" onClick={() => deleteVisit(visit.id)}>Delete</button></div>
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

      {certificationModalOpen && (
        <div className="modal" role="dialog" aria-modal="true" aria-labelledby="certificationModalTitle" onMouseDown={(event) => { if (event.target === event.currentTarget) setCertificationModalOpen(false); }}>
          <section className="modal-panel">
            <div className="modal-head"><div><p className="eyebrow">CREDENTIAL EDITOR</p><h3 id="certificationModalTitle">{certificationDraft.id ? "Edit certification" : "New certification"}</h3></div><button className="modal-close" type="button" aria-label="Close certification editor" onClick={() => setCertificationModalOpen(false)}>×</button></div>
            <form id="certificationForm" onSubmit={saveCertification}>
              <label>Title<input name="title" value={certificationDraft.title} onChange={updateCertification} placeholder="Security+" required /></label>
              <label>Issuer<input name="issuer" value={certificationDraft.issuer} onChange={updateCertification} placeholder="CompTIA" required /></label>
              <label>Date issued<input name="issued_on" type="date" value={certificationDraft.issued_on || ""} onChange={updateCertification} /></label>
              <label>Credential URL<input name="credential_url" type="url" value={certificationDraft.credential_url} onChange={updateCertification} placeholder="https://..." /></label>
              <label className="modal-full">Certificate image<input name="imageFile" type="file" accept="image/jpeg,image/png,image/webp,image/avif" onChange={updateCertification} /><span className="file-help">JPG, PNG, WEBP, or AVIF · max 5 MB {certificationDraft.imageName ? `· ${certificationDraft.imageName}` : ""}</span></label>
              <label className="modal-full">Description<textarea name="description" value={certificationDraft.description} onChange={updateCertification} rows="4" placeholder="What this credential demonstrates..." /></label>
              {certificationDraft.image_url ? <img className="certification-preview" src={certificationDraft.image_url} alt="Current certificate" /> : null}
              <p className="status modal-full" role="status">{certificationStatus}</p>
              <div className="modal-actions modal-full"><button className="small-btn" type="button" onClick={() => setCertificationModalOpen(false)}>Cancel</button><button className="button primary" type="submit">Save certification</button></div>
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
