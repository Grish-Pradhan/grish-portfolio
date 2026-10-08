// Runs before styles load so a saved theme never flashes the opposite palette.
(() => {
  const key = "portfolioTheme";
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const listeners = new Set();
  const valid = value => value === "light" || value === "dark";
  const saved = () => { try { return localStorage.getItem(key); } catch { return null; } };
  let choice = saved();
  let theme;
  const apply = () => {
    const next = valid(choice) ? choice : media.matches ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    document.documentElement.style.colorScheme = next;
    if (theme !== next) { theme = next; listeners.forEach(listener => listener()); }
  };
  window.portfolioTheme = Object.freeze({
    getSnapshot: () => theme,
    set: next => {
      if (!valid(next)) return;
      choice = next;
      try { localStorage.setItem(key, next); } catch { /* The theme still works without storage. */ }
      apply();
    },
    subscribe: listener => { listeners.add(listener); return () => listeners.delete(listener); }
  });
  media.addEventListener("change", apply);
  window.addEventListener("storage", event => {
    if (event.key === key || event.key === null) { choice = saved(); apply(); }
  });
  apply();
})();
