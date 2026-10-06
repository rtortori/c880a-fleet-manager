"use strict";

// Pure fleet-view rules shared by the browser and the fixture tests. These
// A failed Redfish check is distinct from an old but otherwise valid reading.
const FleetView = (() => {
  const PAGE_SIZES = [10, 25, 50];
  const FACETS = [
    {key: "health", label: "Health", choices: ["OK", "Warning", "Critical", "Unknown", "Check failed", "No data", "Offboarded"]},
    {key: "power", label: "Power", choices: ["On", "Off", "Unknown", "No data", "Offboarded"]},
    {key: "exporter", label: "Exporter", choices: ["Running", "Stopped"]},
    {key: "model", label: "Model"},
  ];

  function freshness(server, now = Date.now()) {
    if (server.discovery?.health_check_state === "failed") return "Check failed";
    if (server.discovery?.health_check_state === "missing") return "No data";
    const checked = Date.parse(server.discovery?.checked_at || "");
    if (!Number.isFinite(checked) || checked > now + 60_000) return "Unknown";
    return "Current";
  }

  function classify(server, key, now = Date.now()) {
    if (key === "exporter") return server.state === "active" && server.exporter_running ? "Running" : "Stopped";
    if (key === "model") return String(server.discovery?.model || "Unknown").trim() || "Unknown";
    if (key === "firmware") return String(server.discovery?.firmware_version || "Unknown").trim() || "Unknown";
    if (server.state !== "active") return "Offboarded";
    const age = freshness(server, now);
    // Failed acquisition belongs to Health. Power is unconfirmed until a
    // successful read; retain the stored last-known state for detail views.
    if (key === "power" && age === "Check failed") return "Unknown";
    if (age !== "Current") return age;
    if (key === "health") {
      const health = server.discovery?.system_status?.Health;
      return ["OK", "Warning", "Critical"].includes(health) ? health : "Unknown";
    }
    if (key === "power") {
      const power = server.discovery?.system_power_state;
      return ["On", "Off"].includes(power) ? power : "Unknown";
    }
    return "Unknown";
  }

  function counts(servers, key, now = Date.now()) {
    const result = new Map();
    for (const server of servers) {
      const label = classify(server, key, now);
      result.set(label, (result.get(label) || 0) + 1);
    }
    return result;
  }

  function filter(servers, query, selections, now = Date.now()) {
    const term = query.trim().toLocaleLowerCase();
    return servers.filter(server => {
      if (term && ![server.name, server.bmc_host, server.discovery?.model]
        .some(part => String(part || "").toLocaleLowerCase().includes(term))) return false;
      return FACETS.every(({key}) => !selections[key] || classify(server, key, now) === selections[key]);
    });
  }

  function page(servers, requestedPage, requestedSize) {
    const size = PAGE_SIZES.includes(requestedSize) ? requestedSize : PAGE_SIZES[0];
    const pages = Math.ceil(servers.length / size);
    const wanted = Number.isInteger(requestedPage) ? requestedPage : 1;
    const current = pages ? Math.min(Math.max(1, wanted), pages) : 0;
    const start = current ? (current - 1) * size : 0;
    return {size, pages, current, start, end: Math.min(start + size, servers.length), rows: servers.slice(start, start + size)};
  }

  function onboarding(server) {
    if (server.state !== "active") return null;
    const labels = {initializing: "Initializing", sensors: "Collecting sensors",
      inventory: "Building inventory", recovering: "Recovering data", incomplete: "Setup incomplete"};
    const stage = server.onboarding_stage;
    return Object.hasOwn(labels, stage) ? [labels[stage], stage === "incomplete" ? "warn" : "neutral"] : null;
  }

  return {FACETS, PAGE_SIZES, freshness, classify, counts, filter, page, onboarding};
})();

if (typeof module !== "undefined") module.exports = FleetView;
