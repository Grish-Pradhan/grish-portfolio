const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const vm = require("node:vm");
const script = readFileSync(require("node:path").join(__dirname, "../public/theme-init.js"), "utf8");

function setup({ saved = null, dark = false, blocked = false } = {}) {
  const storage = new Map(saved ? [["portfolioTheme", saved]] : []);
  const events = {};
  const media = { matches:dark, addEventListener:(_, callback) => { events.system = callback; } };
  const root = { dataset:{}, style:{} };
  const window = { matchMedia:() => media, addEventListener:(name, callback) => { events[name] = callback; } };
  const localStorage = {
    getItem:key => { if (blocked) throw Error("Blocked"); return storage.get(key) ?? null; },
    setItem:(key, value) => { if (blocked) throw Error("Blocked"); storage.set(key, value); }
  };
  vm.runInNewContext(script, { window, document:{ documentElement:root }, localStorage });
  return { theme:window.portfolioTheme, root, storage, events, media };
}

test("uses the system preference before a choice is saved", () => {
  assert.equal(setup().theme.getSnapshot(), "light");
  assert.equal(setup({ dark:true }).theme.getSnapshot(), "dark");
});
test("saved choice takes priority over the operating system", () => {
  const { theme, root } = setup({ saved:"light", dark:true });
  assert.equal(theme.getSnapshot(), "light");
  assert.equal(root.style.colorScheme, "light");
});
test("invalid stored values fall back to the system", () => {
  assert.equal(setup({ saved:"invalid", dark:true }).theme.getSnapshot(), "dark");
});
test("toggle persists and notifies subscribers only when changed", () => {
  const { theme, root, storage } = setup();
  let calls = 0;
  const unsubscribe = theme.subscribe(() => calls++);
  theme.set("dark"); theme.set("dark"); theme.set("invalid");
  assert.equal(calls, 1);
  assert.equal(root.dataset.theme, "dark");
  assert.equal(storage.get("portfolioTheme"), "dark");
  unsubscribe(); theme.set("light");
  assert.equal(calls, 1);
});
test("keeps working when storage is blocked", () => {
  const { theme } = setup({ blocked:true });
  theme.set("dark");
  assert.equal(theme.getSnapshot(), "dark");
});
test("follows system changes until the visitor makes a choice", () => {
  const { theme, media, events } = setup();
  media.matches = true; events.system();
  assert.equal(theme.getSnapshot(), "dark");
  theme.set("light"); events.system();
  assert.equal(theme.getSnapshot(), "light");
});
test("syncs another tab's choice and handles cleared storage", () => {
  const { theme, events, storage } = setup();
  storage.set("portfolioTheme", "dark"); events.storage({ key:"portfolioTheme" });
  assert.equal(theme.getSnapshot(), "dark");
  storage.clear(); events.storage({ key:null });
  assert.equal(theme.getSnapshot(), "light");
});
