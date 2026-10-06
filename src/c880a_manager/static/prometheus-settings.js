"use strict";

const PrometheusView = {
  create({api, element, active}) {
    const form = element("prometheus-settings-form");
    const toggle = element("prometheus-enabled");
    const feedback = element("prometheus-feedback");
    const keys = ["scrape_interval", "scrape_timeout", "retention_hours", "storage_gib"];
    let applied = null, status = null, busy = false, refreshing = false, revision = 0, operation = null;
    // Help remains available while settings are locked; it never submits or changes drafts.
    const help = [...form.querySelectorAll(".prometheus-help")];
    let openHelp = null, pinnedHelp = null;
    function closeHelp() {
      for (const item of help) {
        item.querySelector("[role=tooltip]").hidden = true;
        item.querySelector("button").setAttribute("aria-expanded", "false");
      }
      openHelp = pinnedHelp = null;
    }
    function positionHelp() {
      if (!openHelp) return;
      const tip = openHelp.querySelector("[role=tooltip]");
      const button = openHelp.querySelector("button").getBoundingClientRect();
      const field = openHelp.closest(".prometheus-setting").getBoundingClientRect();
      const height = tip.getBoundingClientRect().height;
      let top = button.bottom;
      if (top + height > window.innerHeight - 8) top = button.top - height;
      top = Math.max(8, Math.min(top, window.innerHeight - height - 8));
      tip.style.top = `${top - field.top}px`;
    }
    function showHelp(item) {
      if (pinnedHelp && pinnedHelp !== item) return;
      closeHelp(); openHelp = item;
      item.querySelector("[role=tooltip]").hidden = false;
      item.querySelector("button").setAttribute("aria-expanded", "true");
      positionHelp();
    }
    for (const item of help) {
      const button = item.querySelector("button");
      item.addEventListener("mouseenter", () => { if (!pinnedHelp) showHelp(item); });
      button.addEventListener("focus", () => { if (!pinnedHelp) showHelp(item); });
      item.addEventListener("mouseleave", () => { if (openHelp === item && !pinnedHelp && document.activeElement !== button) closeHelp(); });
      button.addEventListener("blur", () => { if (openHelp === item && !pinnedHelp && !item.matches(":hover")) closeHelp(); });
      button.addEventListener("click", () => {
        if (pinnedHelp === item) closeHelp();
        else { closeHelp(); showHelp(item); pinnedHelp = item; }
      });
    }
    window.addEventListener("resize", positionHelp);
    window.addEventListener("scroll", positionHelp, true);
    document.addEventListener("keydown", event => { if (event.key === "Escape" && openHelp) closeHelp(); });
    document.addEventListener("pointerdown", event => { if (openHelp && !openHelp.contains(event.target)) closeHelp(); });
    function message(text) { feedback.textContent = text; }
    function formError(text) {
      const error = element("prometheus-settings-error");
      error.hidden = false; error.textContent = text; error.focus();
    }
    function controls() {
      const locked = busy || operation !== null || !applied || status?.state === "applying" || status?.state === "unconfirmed";
      toggle.disabled = locked;
      form.querySelectorAll("input, button[type=submit]").forEach(control => { control.disabled = locked; });
      element("prometheus-recover").hidden = !status?.recovery_required;
      element("prometheus-recover").disabled = busy;
      element("prometheus-check-status").hidden = operation === null;
    }
    function limitsNotice() {
      const reduced = applied && (Number(form.elements.namedItem("retention_hours").value) < applied.retention_hours ||
        Number(form.elements.namedItem("storage_gib").value) < applied.storage_gib);
      element("prometheus-retention-note").hidden = !reduced;
    }
    function fill() {
      if (!applied) return;
      for (const key of keys) form.elements.namedItem(key).value = applied[key];
      limitsNotice();
    }
    function render(value, fillDrafts) {
      status = value;
      applied = value.settings;
      toggle.checked = value.enabled === true;
      const states = {running: "Running", disabled: "Disabled", unavailable: "Unavailable", applying: "Applying…", unconfirmed: "Recovery not confirmed"};
      element("prometheus-state").textContent = states[value.state] || "Unavailable";
      element("prometheus-discovery").textContent = value.discovery_state === "waiting" ? "Waiting for discovery…" :
        value.discovery_state === "incomplete" ? "Discovery incomplete · check Targets" : value.discovery_state === "disabled" ? "Discovery stopped" : value.discovery_state === "ready" ? "Discovery current" : "Discovery unavailable";
      element("prometheus-discovered").textContent = `${value.discovered_exporters ?? "Unknown"} of ${value.claimed_exporters} claimed`;
      element("prometheus-scrapes").textContent = value.discovered_exporters === null ? "Unknown" : `${value.successful_scrapes} of ${value.discovered_exporters} discovered`;
      element("prometheus-last-check").textContent = value.checked_at ? new Date(value.checked_at * 1000).toLocaleString() : "Unavailable";
      element("prometheus-last-discovery").textContent = value.last_discovery_at ? new Date(value.last_discovery_at * 1000).toLocaleString() : "Not yet confirmed";
      element("prometheus-url").textContent = value.url;
      element("prometheus-open").href = "/prometheus/";
      element("prometheus-operation").hidden = !value.operation;
      if (value.operation) {
        const labels = {preparing: "Preparing", applying: "Applying", applied: "Applied", rejected: "Rejected", reverted: "Reverted", unconfirmed: "Not confirmed"};
        element("prometheus-operation-summary").textContent = `Last operation · ${labels[value.operation.status] || "Unknown"}`;
        element("prometheus-operation-detail").textContent = value.operation.reason || (value.operation.status === "applied" ? "Changes applied." : "");
        element("prometheus-operation-id").textContent = `Operation ${value.operation.id}`;
      }
      if (fillDrafts) fill(); else limitsNotice();
      if (operation && value.operation?.id === operation && ["applied", "reverted", "rejected"].includes(value.operation.status)) {
        message(value.operation.reason || "Changes applied.");
        const accepted = value.operation.status === "applied";
        operation = null;
        if (accepted && busy === "settings") fill();
      }
      controls();
    }
    async function refresh(fillDrafts = false) {
      if (!active() || refreshing) return;
      refreshing = true;
      const epoch = revision;
      try {
        const value = await api("/api/prometheus/status", "GET", null, 10000);
        if (active() && epoch === revision) render(value, fillDrafts);
      } catch {
        if (active() && epoch === revision) {
          element("prometheus-state").textContent = "Status unavailable";
          element("prometheus-discovery").textContent = "Discovery unavailable";
          element("prometheus-discovered").textContent = "Unknown";
          element("prometheus-scrapes").textContent = "Unknown";
          status = null; applied = null; controls();
          message("Could not check Prometheus. Retry status.");
          element("prometheus-check-status").hidden = false;
        }
      } finally { refreshing = false; }
    }
    async function mutate(path, method, values, kind) {
      if (busy || operation !== null) return;
      const epoch = revision;
      busy = kind;
      operation = crypto.randomUUID().replaceAll("-", "");
      controls(); message("Applying…");
      try {
        const result = await api(path, method, {...values, operation_id: operation});
        if (epoch !== revision) return;
        if (result.id === operation && ["applied", "reverted", "rejected"].includes(result.status)) {
          operation = null;
          message(result.reason || "Changes applied.");
          if (kind === "settings" && result.status !== "applied") formError(result.reason || "Could not apply settings.");
          await refresh(kind === "settings" && result.status === "applied");
        }
      } catch (error) {
        if (epoch === revision) {
          if (error.status && error.status < 500) operation = null;
          const text = `${error.message} Check status before trying again.`;
          message(text);
          if (kind === "settings") formError(text);
        }
      } finally {
        if (epoch === revision) { busy = false; await refresh(); controls(); }
      }
    }
    toggle.addEventListener("change", () => {
      const enabled = toggle.checked;
      toggle.checked = applied?.enabled === true;
      mutate("/api/configuration/prometheus/enabled", "PATCH", {enabled}, "toggle");
    });
    form.addEventListener("input", limitsNotice);
    form.addEventListener("submit", event => {
      event.preventDefault();
      element("prometheus-settings-error").hidden = true;
      if (!applied || !form.reportValidity()) return;
      const values = {enabled: applied.enabled};
      for (const key of keys) values[key] = Number(form.elements.namedItem(key).value);
      if (values.scrape_timeout > values.scrape_interval) { formError("Scrape timeout must not exceed the scrape interval."); return; }
      mutate("/api/configuration/prometheus", "PUT", values, "settings");
    });
    element("prometheus-check-status").addEventListener("click", async () => {
      await refresh();
      if (operation && status && status.state !== "applying" && status.state !== "unconfirmed") {
        operation = null; message("Current settings checked. The previous request was not confirmed; review before applying again."); controls();
      }
    });
    element("prometheus-recover").addEventListener("click", async () => {
      if (busy || !status?.operation?.id) return;
      const epoch = revision;
      busy = "recovery"; controls(); message("Recovering Prometheus…");
      try {
        const result = await api("/api/configuration/prometheus/recover", "POST", {operation_id: status.operation.id});
        if (epoch !== revision) return;
        operation = null; message(result.reason || "Prometheus recovered.");
      } catch (error) { if (epoch === revision) message(error.message); }
      finally { if (epoch === revision) { busy = false; await refresh(); controls(); } }
    });
    setInterval(() => { if (document.visibilityState === "visible") refresh(); }, 15000);
    return {refresh, reset() {
      revision++; applied = null; status = null; busy = false; operation = null;
      closeHelp(); form.reset(); toggle.checked = false; message(""); controls();
      element("prometheus-settings-error").hidden = true;
      element("prometheus-operation").hidden = true;
      for (const id of ["prometheus-state", "prometheus-discovery", "prometheus-discovered", "prometheus-scrapes", "prometheus-last-check", "prometheus-last-discovery", "prometheus-url"]) element(id).textContent = "";
    }};
  }
};
