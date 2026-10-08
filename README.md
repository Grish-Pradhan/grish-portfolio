# Grish Portfolio

React portfolio and admin dashboard, built with Vite and served by a Node.js/Express API. Supabase stores the profile, projects, and contact messages.

## Development

Install dependencies and start both the API and Vite development server:

```bash
npm install
npm run dev
```

Open `http://localhost:5173`. Express runs on port `3000`; Vite proxies `/api` requests to it. The admin dashboard is at `http://localhost:5173/admin/`.

## Explorable portfolio

The homepage (`/`, also `/world`) is a procedural Three.js island. `/portfolio` retains the standard website, and the dedicated `/about`, `/projects`, `/certifications`, `/achievements`, `/contact`, and `/certificate/:id` routes remain available.

Visitors can orbit the island, switch to walking (WASD/arrows, drag to look, Q/E to turn), use touch direction buttons, and travel directly to five exhibits. Buildings and floating labels open keyboard-accessible reading panels. Certificates enlarge without cropping, with original document and verification links where available. Reduced-motion preferences disable decorative movement and travel animation. Unsupported WebGL browsers receive direct links to the standard pages.

The exhibits read the existing `/api/site-data` payload; no additional database or duplicated portfolio records are used. The admin dashboard’s **Portfolio world** section links each exhibit to its existing content editor. Profile, projects, credentials, and the milestone timeline refresh from the API every 15 seconds in visible tabs. Contact notes use the existing `/api/contact` inbox. Island geometry and paths are maintained in code, not in the content editors.

For a local visual preview using the configured remote Supabase API without local server secrets:

```bash
npx vite --host 127.0.0.1 --mode remote-preview
```

This mode uses the public publishable key. It reads the real portfolio; admin edits and contact submissions would also reach the real API. Use the normal `npm run dev` workflow for isolated local API development.

## Production build

```bash
npm run build
npm start
```

Express serves the generated files from `dist/` on port `3000`. `start-server.bat` runs these steps on Windows. Publish the contents of `dist/` for static hosting.

## Supabase setup

Run `supabase/setup.sql` in the Supabase SQL Editor. It creates the tables and policies and can be rerun safely.

The same setup now creates the `certifications` table and the public `portfolio-assets` Storage bucket used for certificate artwork. Admin uploads are handled server-side with the Supabase secret; keep that secret out of `public/config.js`.

For local Express development, set these values in the ignored `.env` file:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_PUBLISHABLE_KEY=your-publishable-key
PORTFOLIO_DB_SECRET_KEY=your-server-only-secret-key
PORTFOLIO_ADMIN_TOKEN=your-long-random-admin-token
```

Keep the secret key and admin token server-side. Rotate any secret key that has been shared.

## Static hosting and Edge Function

The static site routes API requests to the Supabase `portfolio-api` Edge Function using the public key in `public/config.js`. Deploy it from the repository root:

```bash
npx supabase functions deploy portfolio-api --project-ref kqdrhwdidjrdbmwteuom
```

In Supabase Edge Function Secrets, set `PORTFOLIO_DB_SECRET_KEY` and `PORTFOLIO_ADMIN_TOKEN`. Publish the Vite build output after deployment. Never add either secret to `public/config.js`.

## Source files

- `client/main.jsx` — public React portfolio
- `client/admin.jsx` — React admin dashboard
- `public/style.css` and `public/admin/dashboard-theme.css` — page styles
- `server.js` — Node.js API and production static server
- `supabase/functions/portfolio-api/index.ts` — deployed Supabase API

## Privacy analytics

Visitor analytics are opt-in. With v3 consent, the site records the page path, visit timestamp, referring hostname, browser major version, OS/device family, CPU and memory buckets, touch capability, network class, coarse screen/pixel/color-depth buckets, language, timezone, and approximate two-letter country code when the edge platform provides it. DNT/GPC signals disable collection. It does not store raw IP addresses, full user agents, exact device models, GPU details, media-device labels, battery state, precise location, or device fingerprints. Visitors who decline are not tracked.
