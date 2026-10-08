import React, { useSyncExternalStore } from "react";
import "./theme.css";

const subscribe = listener => window.portfolioTheme.subscribe(listener);
const getSnapshot = () => window.portfolioTheme.getSnapshot();
export const useTheme = () => useSyncExternalStore(subscribe, getSnapshot);

export function ThemeToggle() {
  const theme = useTheme();
  const next = theme === "dark" ? "light" : "dark";
  return <button className="theme-toggle" type="button" aria-label={`Switch to ${next} mode`} title={`Switch to ${next} mode`} onClick={() => window.portfolioTheme.set(next)}>
    <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
      {theme === "dark" ? <><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.4 1.4m11.2 11.2L19 19M5 19l1.4-1.4M17.6 6.4 19 5" /></> : <path d="M20.6 14.2A9 9 0 0 1 9.8 3.4 9 9 0 1 0 20.6 14.2Z" />}
    </svg>
  </button>;
}
