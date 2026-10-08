# Theme and admin dashboard verification

## Automated checks

- `node --test tests/theme.test.cjs`: seven tests covering system preference,
  saved preference, invalid values, persistence, subscriptions, blocked storage,
  and cross-tab synchronization.
- `npm run build`: both public and admin entry points build successfully.
- `git diff --check`: no whitespace errors.

## Browser checks

Verified at desktop and 390px mobile width:

- Public navigation and admin login expose an accessible theme toggle.
- The selected theme survives reloads and synchronizes between open tabs.
- The island changes sky, fog, lighting, water, and stars without resetting
  the camera or exhibit state; its reading panels also follow the theme.
- Admin navigation, metric cards, analytics, certificate previews, and editors
  remain readable in both themes without page-level horizontal overflow.
- Visitor charts render horizontal bars and provide an expandable data table.
- Editor dialogs trap keyboard focus, close on Escape, and restore focus.
- Certificate totals initialize when an existing admin session is restored.

## Safe local admin preview

Run `node scripts/preview-admin-ui.mjs`, then open
`http://127.0.0.1:5173/admin/` using the dummy token `preview-only`.
The loopback fixture server serves sample data and rejects writes. It is not
part of the production bundle and does not require a production admin token.
No production content or authentication settings were changed for UI testing.
