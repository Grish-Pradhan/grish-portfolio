# Portfolio world verification

Verified on 8 October 2026 in the browser using the Vite remote-preview mode.

## Confirmed

- Production build completes; Three.js remains in a dynamically loaded chunk.
- Public site-data endpoint returns Grish Pradhan, 0 projects, and 12 credentials.
- Desktop welcome and overview render the procedural island with five labeled exhibits.
- Walking changes the camera position using a held W key.
- Quick travel reaches the credential gallery and enables its nearby-exhibit button.
- Clicking a physical frame with the mouse opens the gallery through raycasting.
- Certificate images load in the scene and in the reading panel. APISEC preview is 2200px wide at source and displays uncropped.
- Enlarging a certificate focuses the back button. Escape closes the panel and restores focus to the opener.
- Help panel receives keyboard focus and traps Tab navigation within its controls.
- Privacy choices block world controls while open; declining restores exploration without sending analytics.
- At 390×844: welcome CTA/footer do not overlap, the island fits the overview, travel controls remain available, and enlarged certificate panels fit the viewport.
- Projects with no published records show an honest empty state.
- Browser error log contains no errors after the final interaction checks.

## Scope and remaining manual checks

- No real contact message was submitted and no production admin content was changed during verification.
- Admin world navigation and editor links are built successfully; authenticated content writes use the unchanged existing admin API and were not exercised in this run.
- The WebGL fallback and device reduced-motion handling are implemented but were not simulated in the browser test.
- The build reports a size warning for the roughly 551kB uncompressed shared Three.js chunk (about 139kB gzip). It loads only with a 3D feature; the world interface itself is a separate smaller chunk.
- Vercel route rewrites preserve the standard `/portfolio` view and dedicated archive/detail pages alongside `/world`.
