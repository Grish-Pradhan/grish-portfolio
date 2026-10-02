# Docker Portfolio

A full-stack personal portfolio website with:

- Responsive modern frontend
- Node.js + Express backend
- SQLite persistent storage
- REST API for profile, projects, and contact messages
- Admin-protected API for managing projects/profile
- Docker + Docker Compose
- Persistent Docker volume

## 1. Start it

From this directory:

```bash
docker compose up -d --build
```

The Dockerfile uses `npm install` so the project does not require a pre-generated lockfile.

Open:

http://localhost:3000

## 2. Stop it

```bash
docker compose down
```

Your SQLite database remains in the `portfolio_data` Docker volume.

## 3. Change the admin token

Edit `docker-compose.yml`:

```yaml
environment:
  ADMIN_TOKEN: replace-with-a-long-random-secret
```

Then recreate:

```bash
docker compose up -d --build
```

Do not use the example token in production.

## 4. API

Public:

- `GET /api/profile`
- `GET /api/projects`
- `GET /api/projects/:id`
- `POST /api/contact`

Admin:

- `GET /api/admin/messages`
- `POST /api/admin/projects`
- `PUT /api/admin/projects/:id`
- `DELETE /api/admin/projects/:id`
- `PUT /api/admin/profile`

Admin endpoints require:

```http
x-admin-token: YOUR_ADMIN_TOKEN
```

Example:

```bash
curl http://localhost:3000/api/admin/messages \
  -H "x-admin-token: change-this-token"
```

## 5. Customize

The easiest files to edit:

- `public/index.html` — page structure
- `public/style.css` — design
- `public/app.js` — frontend behavior
- `server.js` — backend/API/database

The initial profile and projects are seeded automatically into SQLite on first startup.

## Production notes

For public deployment, put the app behind HTTPS/reverse proxy (Nginx, Caddy, Traefik, etc.), change the admin token to a strong secret, and consider adding proper authentication/rate limiting before exposing admin APIs.


## Admin Dashboard

Open:

http://localhost:3000/admin

Use the `ADMIN_TOKEN` value from `docker-compose.yml`.

The dashboard provides:

- Project create/edit/delete
- Featured project controls
- Profile editing
- Contact message viewer
- Session-based admin token storage

The token is sent to protected API endpoints using the `x-admin-token` header.

For public deployment, replace the example `ADMIN_TOKEN` with a long random secret and put the application behind HTTPS.


### If the browser shows an unstyled admin page

Rebuild so Docker gets the latest admin assets:

```powershell
docker compose down
docker compose build --no-cache
docker compose up -d
```

Then hard-refresh the browser with `Ctrl+F5`.
