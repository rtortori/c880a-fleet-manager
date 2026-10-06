"use strict";

// The engine never receives manager cookies. This local guard observes the
// existing session without renewing idle life, and clears views on expiry.
(() => {
  if (document.querySelector(".prometheus-state")) {
    try { document.documentElement.dataset.theme = localStorage.getItem("c880a-appearance") === "light" ? "light" : "dark"; } catch {}
  }
  const nativeFetch = window.fetch.bind(window);
  let leaving = false;
  function signIn() {
    if (leaving) return;
    leaving = true;
    const destination = location.pathname + location.search + location.hash;
    document.body?.replaceChildren();
    location.replace(`/?prometheus_return=${encodeURIComponent(destination)}#/servers`);
  }
  window.fetch = async (...args) => {
    const response = await nativeFetch(...args);
    if (response.status === 401) signIn();
    return response;
  };
  async function observe() {
    try {
      const response = await nativeFetch("/api/session?observe=1", {cache: "no-store", credentials: "same-origin"});
      if (response.status === 401 || response.status === 403) { signIn(); return; }
      if (response.ok && (await response.json()).password_change_required) signIn();
    } catch { /* Native reads and the state page expose connection failure. */ }
  }
  let lastTouch = 0;
  for (const type of ["pointerdown", "keydown", "scroll"]) document.addEventListener(type, event => {
    if (!event.isTrusted || leaving || Date.now() - lastTouch < 30000) return;
    lastTouch = Date.now();
    nativeFetch("/api/session", {cache: "no-store", credentials: "same-origin"})
      .then(response => { if (response.status === 401) signIn(); }).catch(() => {});
  }, {capture: true, passive: true});
  if (typeof BroadcastChannel !== "undefined") {
    const channel = new BroadcastChannel("c880a-auth");
    channel.addEventListener("message", event => { if (event.data?.type === "signed-out") signIn(); });
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden) observe(); });
  document.querySelector("h1")?.focus({preventScroll: true});
  observe();
  setInterval(observe, 15000);
})();
