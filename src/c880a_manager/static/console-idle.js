"use strict";

// Only trusted operator input renews the lease. Viewer frames, fetches,
// WebSocket traffic, and this status timer deliberately do not.
(() => {
  const viewer = document.getElementById("console-viewer");
  const status = document.getElementById("console-idle-status");
  const warning = document.getElementById("console-idle-warning");
  const expired = document.getElementById("console-expired");
  const keepOpen = document.getElementById("console-keep-open");
  let deadline = 0;
  let lastSent = 0;
  let renewing = false;
  let ended = false;

  function endConsole() {
    if (ended) return;
    ended = true;
    deadline = 0;
    viewer.remove();
    status.textContent = "Console session ended";
    warning.hidden = true;
    keepOpen.hidden = true;
    expired.hidden = false;
  }

  function showRemaining() {
    if (ended || !deadline) return;
    const seconds = Math.max(0, Math.ceil((deadline - performance.now()) / 1000));
    if (seconds === 0) {
      // The server is authoritative; check once before ending locally.
      void refreshStatus();
      return;
    }
    const minutes = String(Math.floor(seconds / 60)).padStart(2, "0");
    const remainder = String(seconds % 60).padStart(2, "0");
    status.textContent = `Idle timeout in ${minutes}:${remainder}`;
    warning.hidden = seconds > 60;
    keepOpen.hidden = false;
  }

  async function refreshStatus() {
    if (ended) return;
    try {
      const response = await fetch("/console/status", {credentials: "same-origin", cache: "no-store"});
      if (response.status === 401 || response.status === 403) { endConsole(); return; }
      if (!response.ok) throw new Error("status unavailable");
      const data = await response.json();
      deadline = performance.now() + data.remaining_seconds * 1000;
      showRemaining();
    } catch (_error) {
      status.textContent = "Connection interrupted; checking console session…";
    }
  }

  async function renew(force = false) {
    if (ended || renewing) return;
    const now = performance.now();
    if (!force && now - lastSent < 5000) return;
    renewing = true;
    lastSent = now;
    try {
      const response = await fetch("/console/activity", {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: {"X-Console-Activity": "1"},
      });
      if (response.status === 401 || response.status === 403) { endConsole(); return; }
      if (!response.ok) throw new Error("activity unavailable");
      warning.hidden = true;
      await refreshStatus();
    } catch (_error) {
      status.textContent = "Connection interrupted; activity was not confirmed";
    } finally {
      renewing = false;
    }
  }

  function handleInput(event) {
    if (event.isTrusted && !ended) void renew();
  }

  function watchInputs(target) {
    for (const type of ["keydown", "pointerdown", "pointermove", "wheel", "touchstart"]) {
      target.addEventListener(type, handleInput, {capture: true, passive: true});
    }
  }

  function watchViewer() {
    try { watchInputs(viewer.contentWindow); }
    catch (_error) { status.textContent = "Console input tracking unavailable; use Keep console open"; }
  }
  viewer.addEventListener("load", watchViewer);
  // A cached viewer can finish loading before this deferred script executes.
  watchViewer();
  keepOpen.addEventListener("click", () => { void renew(true); });
  void refreshStatus();
  setInterval(showRemaining, 1000);
  setInterval(() => { void refreshStatus(); }, 5000);
})();
