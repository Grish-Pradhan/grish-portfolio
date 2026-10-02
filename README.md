# Grish Portfolio

React portfolio and admin dashboard, built with Vite and served by a Node.js/Express API. Supabase stores the profile, projects, and contact messages.

## Development

Install dependencies and start both the API and Vite development server:

```bash
npm install
npm run dev
```

Open `http://localhost:5173`. Express runs on port `3000`; Vite proxies `/api` requests to it. The admin dashboard is at `http://localhost:5173/admin/`.

## Production build

```bash
npm run build
npm start
```

Express serves the generated files from `dist/` on port `3000`. `start-server.bat` runs these steps on Windows. Publish the contents of `dist/` for static hosting.

## Supabase setup

Run `supabase/setup.sql` in the Supabase SQL Editor. It creates the tables and policies and can be rerun safely.

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

Visitor analytics are opt-in. With consent, the site records only the page path, visit timestamp, and referring hostname. It does not store raw IP addresses, precise location, or device fingerprints. Run `supabase/setup.sql` again to add the visits table to an existing project; visitors who decline are not tracked.
