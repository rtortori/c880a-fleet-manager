"use strict";

let csrf = "";
let identity = null;
let passwordUser = null;
let authEpoch = 0;
let restoreReview = null;
let restorePollTimer = null;
let backupAbortController = null;
let restorePreviewController = null;
let restorePreviewRevision = 0;
let restoreCommitLocked = false;
let restoreUnknownContext = null;
let restoreLastOperationId = "";
const authChannel = typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel("c880a-auth");
let servers = [];
let onboardingJobs = [];
let onboardingJobsPolling = false;
const onboardingJobStates = new Map();
const fleetSelections = Object.create(null);
let fleetPage = 1;
let currentDetail = null;
let currentMetric = null;
let chartRequest = 0;
let chartSignature = "";
let chartRefreshPending = 0;
let catalogRequest = 0;
let catalogSignature = "";
let inventorySnapshot = null;
let inventoryServerId = null;
let inventoryCategory = null;
let inventoryPage = 0;
let inventoryRequest = 0;
let inventorySignature = "";
let inventoryExpanded = new Set();
let inventorySelectedSource = null;
let generalRequest = 0;
let liveRequest = 0;
let metricsServerId = null;
let liveRenderedServerId = null;
let lastSidebarRoute = null;
let deploymentLastAt = 0;
let deploymentWatchers = 0;
let connectionLost = false;
let connectionClosed = false;
let connectionCheckRunning = false;
let connectionFailures = 0;
const liveSignatures = new Map();
const livePending = new Set();
const liveRefreshTimers = new Map();
const $ = id => document.getElementById(id);
const prometheusView = PrometheusView.create({api, element: $, active: () => identity?.role === "admin" && location.hash === "#/configuration/prometheus" && !connectionLost});
const show = (id, visible) => { $(id).hidden = !visible; };
let displayedBuild = "";
async function refreshBuildInfo() {
  try {
    const response = await fetch("/api/version", {cache: "no-store", credentials: "same-origin"});
    if (!response.ok) return;
    const info = await response.json();
    if (typeof info.version !== "string" || info.version.length > 64 ||
        !/^[0-9a-f]{8}$/.test(info.build)) return;
    const current = `${info.version}:${info.build}`;
    if (displayedBuild && displayedBuild !== current) {
      say("The application was updated. Reload this page to use the latest version.");
      return;
    }
    displayedBuild = current;
    $("app-version-text").textContent = `v${info.version}`;
    $("app-version").hidden = false;
  } catch { /* The connection monitor handles an unreachable manager. */ }
}
refreshBuildInfo();
setInterval(() => { if (document.visibilityState === "visible") refreshBuildInfo(); }, 60000);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") refreshBuildInfo();
});
function setSidebarExpanded(group, expanded) {
  const heading = $(`${group}-heading`);
  const panel = $(`${group}-nav`);
  if (!expanded && panel.contains(document.activeElement)) heading.focus();
  heading.setAttribute("aria-expanded", String(expanded));
  panel.setAttribute("aria-hidden", String(!expanded));
  panel.inert = !expanded;
  panel.classList.toggle("is-collapsed", !expanded);
}
let noticeTimer = null;
function say(text, {autoDismissMs = 0} = {}) {
  if (noticeTimer !== null) clearTimeout(noticeTimer);
  noticeTimer = null;
  $("notice").textContent = text;
  $("workspace-notice-text").textContent = text;
  $("workspace-notice").classList.toggle("has-message", Boolean(text));
  $("dismiss-workspace-notice").hidden = !text;
  if (text && autoDismissMs > 0) {
    noticeTimer = setTimeout(() => say(""), autoDismissMs);
  }
}
$("dismiss-workspace-notice").addEventListener("click", () => say(""));
const THEME_STORAGE_KEY = "c880a-appearance";
function applyTheme(choice, persist = false) {
  const theme = choice === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  for (const button of document.querySelectorAll("[data-theme-choice]")) {
    button.setAttribute("aria-pressed", String(button.dataset.themeChoice === theme));
  }
  if (persist) {
    try { localStorage.setItem(THEME_STORAGE_KEY, theme); } catch { /* Private browsing may block storage. */ }
  }
}
let savedTheme = "dark";
try { savedTheme = localStorage.getItem(THEME_STORAGE_KEY) || "dark"; } catch { /* Use the default. */ }
applyTheme(savedTheme);
for (const button of document.querySelectorAll("[data-theme-choice]")) {
  button.addEventListener("click", () => applyTheme(button.dataset.themeChoice, true));
}
document.addEventListener("click", event => {
  const menu = $("account-menu");
  if (menu.open && !menu.contains(event.target)) menu.open = false;
});

async function api(path, method = "GET", data = null, timeoutMs = 0, extraHeaders = {}) {
  if (connectionLost) throw new Error("Manager connection lost. Retry the connection first.");
  const requestEpoch = authEpoch;
  const headers = {...extraHeaders};
  if (data !== null) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrf;
  const controller = timeoutMs ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  let response;
  try {
    response = await fetch(path, {method, headers, credentials: "same-origin",
      body: data === null ? null : JSON.stringify(data), signal: controller?.signal});
  } catch (error) {
    if (error.name === "AbortError") throw new Error("The read timed out. Retry when the server is available.");
    throw error;
  } finally { if (timer) clearTimeout(timer); }
  const result = await response.json();
  if (requestEpoch !== authEpoch && path !== "/api/login") throw new Error("Session changed. Sign in again.");
  if (response.status === 401 && path !== "/api/login" && identity)
    showLogin(identity.password_change_required ? "Setup session ended. Sign in and change the password." :
      "Session ended. Sign in to continue.");
  if (response.status === 403 && result.detail === "Invalid CSRF token" && identity) showLogin("Session changed. Sign in to continue.");
  if (!response.ok) {
    const error = new Error(typeof result.detail === "string" ? result.detail : `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return result;
}

function node(tag, text = "", className = "") {
  const item = document.createElement(tag);
  item.textContent = text == null ? "" : String(text);
  if (className) item.className = className;
  return item;
}

function badge(text, tone = "neutral") { return node("span", text, `badge ${tone}`); }
function value(value) { return value === null || value === undefined || value === "" ? "—" : String(value); }
function bmcEndpoint(server) {
  const host = server.bmc_host.includes(":") ? `[${server.bmc_host}]` : server.bmc_host;
  return `${host}:${server.bmc_port || 443}`;
}
function bmcUrl(server, path) {
  // Onboarding accepts only IP addresses; this constructs a fixed HTTPS route.
  const host = server.bmc_host.includes(":") ? `[${server.bmc_host}]` : server.bmc_host;
  return `https://${host}:${server.bmc_port || 443}/${path}`;
}
function health(server) {
  if (server.state !== "active") return ["Offboarded", "neutral"];
  const state = FleetView.classify(server, "health");
  if (state === "OK") return ["Healthy", "good"];
  if (state === "Warning") return ["Warning", "warn"];
  if (state === "Critical") return ["Critical", "bad"];
  if (state === "Check failed") return ["Check failed", "warn"];
  if (state === "No data") return ["No health data", "warn"];
  return ["Unknown", "neutral"];
}
function collection(server) {
  if (server.state !== "active") return ["Stopped", "neutral"];
  return server.exporter_running ? ["Exporter running", "good"] : ["Exporter stopped", "bad"];
}

function formatGiB(bytes) { return `${(bytes / (1024 ** 3)).toFixed(1)} GiB`; }
function formatResidentMemory(bytes) { return bytes >= 1024 ** 3 ? formatGiB(bytes) : `${(bytes / (1024 ** 2)).toFixed(0)} MiB`; }
let hostResourcesPending = false;
async function refreshHostResources() {
  if (!identity || hostResourcesPending || document.visibilityState !== "visible") return;
  hostResourcesPending = true;
  try {
    const data = await api("/api/runtime/resources");
    if (!identity) return;
    if (!data.available || !Number.isFinite(data.host?.memory_total_bytes) ||
        !Number.isFinite(data.host?.memory_used_bytes) || !Number.isFinite(data.host?.memory_percent))
      throw new Error("Resource sample unavailable");
    const hostCpu = Number.isFinite(data.host.cpu_percent) ? `${data.host.cpu_percent.toFixed(1)}%` : "Measuring…";
    const hostMemory = `${formatGiB(data.host.memory_used_bytes)} / ${formatGiB(data.host.memory_total_bytes)} (${data.host.memory_percent.toFixed(1)}%)`;
    $("host-resources-summary").textContent = `Manager host · CPU ${hostCpu} · Memory ${data.host.memory_percent.toFixed(1)}%`;
    $("host-resources-host").textContent = `CPU ${hostCpu} · Memory ${hostMemory}`;
    const appCpu = Number.isFinite(data.app?.cpu_percent_of_host) ? `${data.app.cpu_percent_of_host.toFixed(1)}% of host` : "Measuring…";
    $("host-resources-app-heading").textContent = data.app.scope === "manager_only" ? "Manager process" : "Manager and accessible child processes";
    $("host-resources-app").textContent = `CPU ${appCpu} · Memory ${formatResidentMemory(data.app.rss_bytes)}`;
  } catch {
    if (!identity) return;
    $("host-resources-summary").textContent = "Manager host · Unavailable";
    $("host-resources-host").textContent = "Resource readings unavailable";
    $("host-resources-app").textContent = "Resource readings unavailable";
  } finally { hostResourcesPending = false; }
}

function renderSummary() {
  const summary = $("fleet-summary"); summary.replaceChildren();
  for (const facet of FleetView.FACETS) {
    const card = node("section", "", "summary-card");
    card.append(node("h3", facet.label, "summary-label"));
    const entries = FleetView.counts(servers, facet.key);
    const labels = facet.choices || [...entries.keys()].sort((a, b) =>
      a === "Unknown" ? 1 : b === "Unknown" ? -1 : a.localeCompare(b));
    const choices = node("div", "", "summary-choices");
    for (const label of labels) {
      const count = entries.get(label) || 0;
      if (!count) continue;
      const button = node("button", "", "summary-choice");
      const tone = ["Critical", "Stopped"].includes(label) ? "bad"
        : ["Warning", "Check failed", "No data", "Off"].includes(label) ? "warn"
        : ["OK", "On", "Running"].includes(label) ? "good" : "neutral";
      button.type = "button";
      button.title = `${facet.label}: ${label} (${count})`;
      button.classList.add(tone);
      button.setAttribute("aria-pressed", String(fleetSelections[facet.key] === label));
      button.setAttribute("aria-label", `${facet.label}: ${label}, ${count} ${count === 1 ? "server" : "servers"}`);
      const displayLabel = facet.key === "health" && label === "OK" ? "Healthy" : label;
      button.append(node("span", displayLabel, "summary-choice-label"), node("strong", count, "summary-choice-count"));
      button.addEventListener("click", () => {
        fleetSelections[facet.key] = fleetSelections[facet.key] === label ? null : label;
        fleetPage = 1;
        renderSummary(); renderServers();
      });
      choices.append(button);
    }
    if (!choices.childElementCount) choices.append(node("span", "No servers", "summary-empty"));
    card.append(choices);
    summary.append(card);
  }
}

const actionsMenu = $("server-actions-menu");
let activeActionsButton = null;
let fleetRenderDeferred = false;
actionsMenu.addEventListener("toggle", () => {
  if (!actionsMenu.matches(":popover-open") && activeActionsButton) {
    activeActionsButton.setAttribute("aria-expanded", "false");
    activeActionsButton = null;
  }
  if (!actionsMenu.matches(":popover-open") && fleetRenderDeferred && identity) renderServers();
});
actionsMenu.addEventListener("keydown", event => {
  if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
  event.preventDefault();
  const items = [...actionsMenu.querySelectorAll('[role="menuitem"]')]
    .filter(item => item.getClientRects().length && !item.disabled);
  if (!items.length) return;
  const current = items.indexOf(document.activeElement);
  const next = event.key === "ArrowDown" ? (current + 1) % items.length : (current - 1 + items.length) % items.length;
  items[next]?.focus();
});

let pendingUnclaim = null;
let unclaimBusy = false;
let pendingServerAction = null;
let actionReturnFocus = null;
let serverActionBusy = false;
let actionCheckRequest = 0;
let actionCheckPending = false;
const activeActionStates = new Set(["sending", "submitted", "running"]);
const actionDisplayNames = {power_on: "Power On", power_off: "Power Off", force_power_off: "Force Power Off",
  reboot_server: "Reboot Server", reboot_bmc: "Reboot BMC", collect_support_bundle: "Collect Tech Support"};
function visiblePowerActions(powerState) {
  if (powerState === "On") return ["power_off", "force_power_off", "reboot_server"];
  if (powerState === "Off") return ["power_on"];
  return [];
}

function actionProgress(job) {
  if (!job || !activeActionStates.has(job.state)) return "";
  return ({power_on: "Powering on", power_off: "Powering off", force_power_off: "Forcing power off", reboot_server: "Restarting server",
    reboot_bmc: "Reconnecting to BMC", collect_support_bundle: "Collecting tech support"})[job.operation] || "Working";
}

function powerIcon(server) {
  const state = server.discovery?.system_power_state;
  const progress = actionProgress(server.active_action);
  const icon = node("span", "⏻", `power-icon ${progress ? "transition" : state === "On" ? "on" : state === "Off" ? "off" : "unknown"}`);
  const label = progress || `Power ${state === "On" || state === "Off" ? state.toLowerCase() : "status unknown"}`;
  icon.setAttribute("role", "img");
  icon.setAttribute("aria-label", label); icon.title = label;
  return icon;
}

function updateDetailPowerIcon(server) {
  const icon = $("detail-power-icon");
  const replacement = powerIcon(server);
  replacement.id = "detail-power-icon";
  icon.replaceWith(replacement);
}

function openServerActionChecking(server, key) {
  pendingServerAction = null;
  actionCheckPending = true;
  $("server-action-confirm-title").textContent = `Checking ${actionDisplayNames[key]}…`;
  $("server-action-target").textContent = `${server.name} · BMC ${bmcEndpoint(server)}`;
  const status = $("server-action-check-status");
  status.dataset.state = "loading";
  status.textContent = "Checking the BMC and available controls. No action has been sent.";
  $("server-action-impact").textContent = "";
  $("server-action-acknowledge").checked = false;
  $("server-action-acknowledge-label").hidden = true;
  $("confirm-server-action").hidden = true;
  $("confirm-server-action").disabled = true;
  $("server-action-confirm-dialog").showModal();
  $("server-action-confirm-title").setAttribute("tabindex", "-1");
  $("server-action-confirm-title").focus();
}

function showServerActionCheckError(message) {
  const status = $("server-action-check-status");
  status.dataset.state = "error";
  status.textContent = message;
  $("server-action-confirm-title").textContent = "Control unavailable";
}

function openServerActionConfirmation(server, key, action) {
  pendingServerAction = {server, key, action};
  $("server-action-confirm-title").textContent = `Confirm ${action.label}?`;
  $("server-action-target").textContent = `${server.name} · BMC ${bmcEndpoint(server)}`;
  $("server-action-check-status").textContent = "";
  $("server-action-check-status").dataset.state = "ready";
  $("server-action-impact").textContent = action.impact;
  $("server-action-acknowledge").checked = false;
  $("server-action-acknowledge-label").hidden = false;
  $("confirm-server-action").hidden = false;
  $("confirm-server-action").disabled = true;
  $("confirm-server-action").textContent = action.label;
  $("server-action-confirm-title").focus();
}

async function refreshServerActionJobs() {
  if (!servers.some(item => item.active_action)) return;
  try {
    const hadActive = servers.some(item => item.active_action);
    await loadServers();
    if (hadActive && !servers.some(item => item.active_action) && currentDetail) {
      const current = servers.find(item => item.id === currentDetail);
      if (current) updateDetailPowerIcon(current);
    }
  } catch { /* The next refresh can retry. */ }
}

$("server-action-acknowledge").addEventListener("change", event => {
  $("confirm-server-action").disabled = !event.target.checked || serverActionBusy;
});
$("cancel-server-action").addEventListener("click", () => {
  if (!serverActionBusy) { actionCheckRequest++; actionCheckPending = false; $("server-action-confirm-dialog").close(); }
});
$("server-action-confirm-dialog").addEventListener("cancel", event => {
  if (serverActionBusy) event.preventDefault();
  else { actionCheckRequest++; actionCheckPending = false; }
});
$("server-action-confirm-dialog").addEventListener("close", () => {
  actionCheckRequest++;
  actionCheckPending = false;
  const target = actionReturnFocus?.isConnected ? actionReturnFocus
    : (currentDetail ? $("detail-actions") : $("server-search"));
  target?.focus();
  actionReturnFocus = null;
  pendingServerAction = null;
});
$("confirm-server-action").addEventListener("click", async () => {
  if (!pendingServerAction || serverActionBusy || !$("server-action-acknowledge").checked) return;
  const {server, key} = pendingServerAction;
  serverActionBusy = true; $("confirm-server-action").disabled = true;
  try {
    const job = await api(`/api/servers/${encodeURIComponent(server.id)}/actions/${encodeURIComponent(key)}`,
      "POST", {expected_host: server.bmc_host, expected_name: server.name, acknowledge_impact: true});
    $("server-action-confirm-dialog").close();
    say(`${key.replaceAll("_", " ")}: ${job.state}.`);
    server.active_action = activeActionStates.has(job.state) ? job : null;
    renderServers();
    await loadServers();
    await refreshServerActionJobs();
    if (currentDetail === server.id) updateDetailPowerIcon(servers.find(item => item.id === server.id) || server);
  } catch (error) { say(error.message); }
  finally { serverActionBusy = false; }
});
setInterval(refreshServerActionJobs, 5000);

function offboard(server) {
  pendingUnclaim = server;
  $("unclaim-target").textContent = `Target: ${server.name} (${bmcEndpoint(server)})`;
  $("unclaim-acknowledge").checked = false;
  $("confirm-unclaim").disabled = true;
  $("unclaim-dialog").showModal();
}
$("unclaim-acknowledge").addEventListener("change", event => {
  $("confirm-unclaim").disabled = !event.target.checked || unclaimBusy;
});
$("close-unclaim").addEventListener("click", () => { if (!unclaimBusy) $("unclaim-dialog").close(); });
$("cancel-unclaim").addEventListener("click", () => { if (!unclaimBusy) $("unclaim-dialog").close(); });
$("unclaim-dialog").addEventListener("cancel", event => { if (unclaimBusy) event.preventDefault(); });
$("confirm-unclaim").addEventListener("click", async () => {
  if (!pendingUnclaim || unclaimBusy || !$("unclaim-acknowledge").checked) return;
  const server = pendingUnclaim;
  unclaimBusy = true;
  $("confirm-unclaim").disabled = true;
  try {
    const result = await api(`/api/servers/${encodeURIComponent(server.id)}`, "DELETE",
      {acknowledge_data_deletion: true});
    $("unclaim-dialog").close();
    pendingUnclaim = null;
    say(result.history_cleanup === "pending" ? `${server.name} unclaimed. Prometheus history cleanup is pending; check Configuration → Prometheus.` :
      `${server.name} unclaimed; its local data was deleted.`, {autoDismissMs: result.history_cleanup === "pending" ? 0 : 5000});
    await loadServers();
  } catch (error) { say(error.message); }
  finally { unclaimBusy = false; }
});

async function openVirtualConsole(server) {
  // Open synchronously with the user gesture so popup blockers do not discard it.
  const target = `c880a-console-${server.id.replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const popup = window.open("about:blank", target, "width=1300,height=860,resizable=yes,scrollbars=yes");
  if (!popup) { say("Allow popups for this manager to open the virtual console."); return; }
  popup.document.title = "Opening C880A console…";
  popup.document.body.textContent = `Connecting to ${server.name} virtual console…`;
  try {
    const result = await api(`/api/servers/${encodeURIComponent(server.id)}/console/start`, "POST");
    const action = new URL(result.launch_url);
    if (action.protocol !== window.location.protocol || action.hostname !== window.location.hostname) {
      throw new Error("Console gateway origin does not match the manager");
    }
    const form = document.createElement("form");
    form.method = "POST"; form.action = action.href; form.target = target;
    const field = document.createElement("input");
    field.type = "hidden"; field.name = "csrf"; field.value = csrf;
    form.append(field); document.body.append(form);
    form.submit(); form.remove();
    popup.opener = null;
    popup.focus();
  } catch (error) {
    popup.close();
    say(`Virtual console unavailable: ${error.message}. Use Open BMC instead.`);
  }
}

function positionActionsMenu(trigger) {
  const rect = trigger.getBoundingClientRect();
  const menuRect = actionsMenu.getBoundingClientRect();
  actionsMenu.style.left = `${Math.max(8, Math.min(rect.right - menuRect.width, window.innerWidth - menuRect.width - 8))}px`;
  actionsMenu.style.top = `${rect.bottom + menuRect.height + 8 > window.innerHeight ? Math.max(8, rect.top - menuRect.height - 5) : rect.bottom + 5}px`;
}

async function prepareMenuAction(server, trigger, key) {
  if (serverActionBusy || actionCheckPending || $("server-action-confirm-dialog").open) return;
  actionReturnFocus = trigger;
  actionsMenu.hidePopover();
  openServerActionChecking(server, key);
  const request = ++actionCheckRequest;
  try {
    const data = await api(`/api/servers/${encodeURIComponent(server.id)}/actions?operation=${encodeURIComponent(key)}`);
    if (request !== actionCheckRequest || !$("server-action-confirm-dialog").open) return;
    if (data.power_state) {
      server.discovery.system_power_state = data.power_state;
      const existing = trigger.closest("tr")?.querySelector(".power-icon");
      if (existing) existing.replaceWith(powerIcon(server));
      if (currentDetail === server.id) updateDetailPowerIcon(server);
      renderSummary();
    }
    if (!data.execution_enabled || data.jobs.some(job => activeActionStates.has(job.state))) {
      showServerActionCheckError("Server controls are unavailable while an action is in progress or disabled on this manager. No action was sent.");
      return;
    }
    const action = data.actions[key];
    if (!action) {
      const discoveryWarning = key === "reboot_bmc" || key === "collect_support_bundle"
        ? "BMC action discovery failed" : "System action discovery failed";
      const checkFailed = (data.power_state == null && ["power_on", "power_off", "force_power_off", "reboot_server"].includes(key))
        || data.warnings?.includes(discoveryWarning);
      showServerActionCheckError(checkFailed
        ? `Could not verify ${actionDisplayNames[key]} because the BMC control check failed. Try again. No action was sent.`
        : `${actionDisplayNames[key]} is not available in the BMC's current state. No action was sent.`);
      return;
    }
    openServerActionConfirmation(server, key, action);
  } catch (error) {
    if (request === actionCheckRequest && $("server-action-confirm-dialog").open) {
      showServerActionCheckError(`Control unavailable: ${error.message}. No action was sent.`);
    }
  } finally {
    if (request === actionCheckRequest) actionCheckPending = false;
  }
}

function openActionsMenu(server, trigger) {
  if (identity?.role !== "admin") return;
  if (actionsMenu.matches(":popover-open")) actionsMenu.hidePopover();
  actionsMenu.replaceChildren();
  const link = (label, href) => {
    const item = node("a", label, "action-menu-item");
    item.href = href; item.target = "_blank"; item.rel = "noopener noreferrer";
    item.setAttribute("role", "menuitem");
    item.addEventListener("click", () => actionsMenu.hidePopover());
    return item;
  };
  // The vendor viewer cannot be deep-linked: Launch H5Viewer initializes the
  // window context first. Start at the BMC root so signed-out users can log in.
  if (server.state === "active") {
    const controls = node("div", "", "action-menu-controls");
    const busy = actionProgress(server.active_action);
    const makeControl = key => {
      const item = node("button", actionDisplayNames[key],
        `action-menu-item ${key === "force_power_off" ? "danger-action" : ""}`);
      item.type = "button"; item.setAttribute("role", "menuitem");
      const parked = key === "collect_support_bundle";
      item.disabled = parked || !server.bmc_actions_enabled || !!busy;
      if (item.disabled && !parked) item.title = busy || "BMC controls are disabled on this manager";
      item.addEventListener("click", () => prepareMenuAction(server, trigger, key));
      if (parked) {
        const wrapper = node("span", "", "parked-action");
        wrapper.title = "Not available at the moment. Collect the support bundle directly from the BMC UI under System Diagnostics.";
        item.setAttribute("aria-description", wrapper.title);
        wrapper.append(item);
        return wrapper;
      }
      return item;
    };
    const group = node("details", "", "action-submenu");
    const heading = node("summary", "Power", "action-menu-item");
    heading.setAttribute("role", "menuitem");
    heading.setAttribute("aria-label", "Power controls");
    const flyout = node("div", "", "action-submenu-panel");
    const keys = visiblePowerActions(server.discovery?.system_power_state);
    if (keys.length) flyout.append(...keys.map(makeControl));
    else flyout.append(node("span", "Power state unknown; controls unavailable.", "action-menu-status"));
    group.append(heading, flyout);
    controls.append(group, makeControl("reboot_bmc"), makeControl("collect_support_bundle"));
    if (busy) controls.append(node("span", `${busy}…`, "action-menu-status"));
    else if (!server.bmc_actions_enabled) controls.append(node("span", "BMC controls are disabled in this manager process.", "action-menu-status"));
    actionsMenu.append(controls);
    const consoleButton = node("button", "Open vKVM console", "action-menu-item");
    consoleButton.type = "button"; consoleButton.setAttribute("role", "menuitem");
    consoleButton.addEventListener("click", () => { actionsMenu.hidePopover(); openVirtualConsole(server); });
    actionsMenu.append(consoleButton);
  }
  actionsMenu.append(link("Open BMC ↗", bmcUrl(server, "")));
  actionsMenu.append(link("Open exporter metrics ↗", server.scrape_url));
  if (server.state === "active") {
    const toggle = node("button", server.manager_metrics_enabled ? "Disable Manager Metrics" : "Enable Manager Metrics", "action-menu-item");
    toggle.type = "button"; toggle.setAttribute("role", "menuitem");
    toggle.addEventListener("click", async () => {
      actionsMenu.hidePopover();
      toggle.disabled = true;
      try {
        const updated = await api(`/api/servers/${encodeURIComponent(server.id)}/manager-metrics`, "PATCH",
          {enabled: !server.manager_metrics_enabled});
        server.manager_metrics_enabled = updated.manager_metrics_enabled;
        renderServers();
        if (currentDetail === server.id && location.hash.endsWith("/metrics")) await showServerMetrics(server.id);
        say(`Manager metrics ${server.manager_metrics_enabled ? "enabled" : "disabled"} for ${server.name}.`);
      } catch (error) { say(error.message); }
    });
    actionsMenu.append(toggle);
  }
  if (server.state === "active" || server.state === "offboarded") {
    const remove = node("button", server.state === "active" ? "Unclaim and delete local data" : "Delete retained target data", "action-menu-item danger-action");
    remove.type = "button"; remove.setAttribute("role", "menuitem");
    remove.addEventListener("click", () => { actionsMenu.hidePopover(); offboard(server); });
    actionsMenu.append(remove);
  }
  activeActionsButton = trigger;
  trigger.setAttribute("aria-expanded", "true");
  actionsMenu.showPopover();
  positionActionsMenu(trigger);
  actionsMenu.querySelector('[role="menuitem"]')?.focus();
}

function renderServers() {
  fleetRenderDeferred = false;
  if (actionsMenu.matches(":popover-open")) actionsMenu.hidePopover();
  const shown = FleetView.filter(servers, $("server-search").value, fleetSelections);
  const paging = FleetView.page(shown, fleetPage, Number($("fleet-page-size").value));
  fleetPage = paging.current || 1;
  const body = $("server-list"); body.replaceChildren();
  $("server-count").textContent = `${shown.length} ${shown.length === 1 ? "result" : "results"} · ${servers.length} fleet total`;
  $("fleet-empty").textContent = servers.length ? "No servers match this view. Clear filters or change the search." : "No servers onboarded yet.";
  show("fleet-empty", shown.length === 0);
  const active = $("fleet-active-filters"); active.replaceChildren();
  for (const facet of FleetView.FACETS) {
    const selected = fleetSelections[facet.key];
    if (!selected) continue;
    const chip = node("button", `${facet.label}: ${selected} ×`, "fleet-filter-chip");
    chip.type = "button"; chip.setAttribute("aria-label", `Remove ${facet.label} filter: ${selected}`);
    chip.addEventListener("click", () => { fleetSelections[facet.key] = null; fleetPage = 1; renderSummary(); renderServers(); });
    active.append(chip);
  }
  if (active.childElementCount) {
    const clear = node("button", "Clear filters", "text-button");
    clear.type = "button";
    clear.addEventListener("click", () => {
      for (const facet of FleetView.FACETS) fleetSelections[facet.key] = null;
      fleetPage = 1; renderSummary(); renderServers();
    });
    active.append(clear);
  }
  show("fleet-active-filters", active.childElementCount > 0);
  $("fleet-page-range").textContent = shown.length ? `Showing ${paging.start + 1}–${paging.end} of ${shown.length}` : "Showing 0 of 0";
  $("fleet-prev").disabled = paging.current <= 1;
  $("fleet-next").disabled = paging.current >= paging.pages;
  renderPageNumbers("fleet-page-numbers", paging.current, paging.pages, number => { fleetPage = number; renderServers(); }, "server");
  for (const server of paging.rows) {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const nameLink = node("a", server.name, "server-link");
    nameLink.href = `#/servers/${encodeURIComponent(server.id)}`;
    nameCell.append(powerIcon(server), nameLink);
    row.append(nameCell);
    const healthCell = document.createElement("td");
    const setup = FleetView.onboarding(server);
    const currentHealth = health(server);
    if (setup) {
      healthCell.classList.add("fleet-onboarding");
      if (["Warning", "Critical", "Check failed"].includes(currentHealth[0])) healthCell.append(badge(...currentHealth));
      healthCell.append(badge(...setup));
    } else healthCell.append(badge(...currentHealth));
    row.append(healthCell);
    const modelCell = node("td", value(server.discovery?.model)); modelCell.title = value(server.discovery?.model); row.append(modelCell);
    row.append(node("td", bmcEndpoint(server)));
    const firmwareCell = node("td", value(server.discovery?.firmware_version)); firmwareCell.title = value(server.discovery?.firmware_version); row.append(firmwareCell);
    const biosCell = node("td", value(server.discovery?.bios_version)); biosCell.title = value(server.discovery?.bios_version); row.append(biosCell);
    const serialCell = node("td", value(server.discovery?.serial_number)); serialCell.title = value(server.discovery?.serial_number); row.append(serialCell);
    const actionCell = node("td", "", "row-actions");
    if (actionProgress(server.active_action)) actionCell.append(node("span", `${actionProgress(server.active_action)}…`, "control-progress"));
    const button = node("button", "⋯", "button action-trigger");
    button.type = "button"; button.setAttribute("aria-label", `More actions for ${server.name}`);
    button.setAttribute("aria-haspopup", "menu"); button.setAttribute("aria-expanded", "false");
    if (identity?.role !== "admin") { button.disabled = true; button.title = "Read-only access"; }
    button.addEventListener("click", () => openActionsMenu(server, button));
    actionCell.append(button);
    row.append(actionCell); body.append(row);
  }
}

function renderPageNumbers(id, current, pages, navigate, subject) {
  const container = $(id); container.replaceChildren();
  let previous = 0;
  const visible = [...new Set([1, current - 1, current, current + 1, pages].filter(number => number >= 1 && number <= pages))].sort((a, b) => a - b);
  for (const number of visible) {
    if (previous && number - previous > 1) container.append(node("span", "…", "page-ellipsis"));
    const button = node("button", String(number), "page-number");
    button.type = "button";
    button.setAttribute("aria-label", `${subject} page ${number}`);
    if (number === current) button.setAttribute("aria-current", "page");
    button.addEventListener("click", () => navigate(number));
    container.append(button);
    previous = number;
  }
}

async function loadServers() {
  servers = await api("/api/servers");
  const filter = $("server-filter"); const selected = filter.value;
  filter.replaceChildren(new Option("All Servers", ""));
  for (const server of servers) filter.add(new Option(`${server.name} (${bmcEndpoint(server)})`, server.id));
  filter.value = selected;
  renderSummary();
  if (actionsMenu.matches(":popover-open")) fleetRenderDeferred = true;
  else renderServers();
}

function renderOnboardingJobs() {
  const container = $("onboarding-jobs");
  container.replaceChildren();
  container.hidden = !identity || identity.role !== "admin" || onboardingJobs.length === 0;
  for (const job of onboardingJobs) {
    const row = node("div", "", `onboarding-job ${job.state}`);
    const copy = node("div", "", "onboarding-job-copy");
    const label = job.state === "running" ? `Onboarding ${job.name} in the background`
      : job.state === "succeeded" ? `${job.name} onboarded` : `Could not onboard ${job.name}`;
    const stage = job.state === "failed"
      ? `${job.error || "Validation failed."} Last stage: ${job.message || "unknown"}`
      : job.message;
    copy.append(node("strong", label), node("span", stage || "Waiting for the BMC…"));
    const actions = node("div", "", "onboarding-job-actions");
    if (job.state !== "running") {
      const dismiss = node("button", "Dismiss", "text-button");
      dismiss.type = "button";
      dismiss.addEventListener("click", async () => {
        try { await api(`/api/onboarding-jobs/${encodeURIComponent(job.id)}`, "DELETE"); await refreshOnboardingJobs(); }
        catch (error) { say(error.message); }
      });
      actions.append(dismiss);
    }
    row.append(copy, actions);
    container.append(row);
  }
}

async function refreshOnboardingJobs() {
  if (!identity || identity.role !== "admin" || onboardingJobsPolling) return;
  onboardingJobsPolling = true;
  try {
    const jobs = await api("/api/onboarding-jobs", "GET", null, 5000);
    const completed = jobs.some(job => job.state === "succeeded" && onboardingJobStates.get(job.id) === "running");
    onboardingJobs = jobs;
    onboardingJobStates.clear();
    for (const job of jobs) onboardingJobStates.set(job.id, job.state);
    renderOnboardingJobs();
    if (completed) await loadServers();
  } catch {
    // A transient poll failure must not recreate a dismissed global notice.
    // Keep the last known job state and try again on the next poll.
  } finally { onboardingJobsPolling = false; }
}

function formatTime(raw) {
  if (!raw) return "—";
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? String(raw) : date.toLocaleString();
}

async function loadEvents() {
  const id = $("server-filter").value;
  const query = id ? `?server_id=${encodeURIComponent(id)}&limit=200` : "?limit=200";
  const events = await api(`/api/events${query}`);
  const body = $("event-list"); body.replaceChildren();
  $("event-count").textContent = `${events.length} ${events.length === 1 ? "event" : "events"}`;
  show("event-empty", events.length === 0);
  for (const event of events) {
    const row = document.createElement("tr");
    const server = servers.find(item => item.id === event.server_id);
    const deviceTime = event.occurred_at && event.time_quality === "plausible"
      ? formatTime(event.occurred_at) : `${event.occurred_at || "—"} (${event.time_quality || "unknown"})`;
    for (const [text, className] of [
      [formatTime(event.observed_at), "mono"], [deviceTime, "mono"], [server?.name || "Unknown source", ""],
    ]) {
      const cell = node("td", text, className); cell.title = String(text); row.append(cell);
    }
    const severityCell = document.createElement("td");
    const severity = event.severity || "Unknown";
    severityCell.append(badge(severity, severity === "Critical" ? "bad" : severity === "Warning" ? "warn" : severity === "OK" ? "good" : "neutral"));
    row.append(severityCell);
    const messageCell = node("td", "", "message-cell");
    const messageLayout = node("div", "", "event-message-layout");
    messageLayout.append(node("span", event.message || "—", "event-message"));
    const viewButton = node("button", "View", "text-button view-event");
    viewButton.setAttribute("aria-label", `View full event from ${server?.name || "unknown source"}`);
    viewButton.addEventListener("click", () => openEvent(event, server));
    messageLayout.append(viewButton); messageCell.append(messageLayout); row.append(messageCell);
    body.append(row);
  }
}

function openEvent(event, server) {
  const fields = $("event-dialog-fields"); fields.replaceChildren();
  for (const [label, raw] of [
    ["Message", event.message], ["Server", server?.name || "Unknown source"],
    ["Severity", event.severity], ["Observed", formatTime(event.observed_at)],
    ["Device time", event.occurred_at && event.time_quality === "plausible" ? formatTime(event.occurred_at) : event.occurred_at],
    ["Time quality", event.time_quality], ["Source", event.source], ["Message ID", event.message_id],
  ]) field(fields, label, raw);
  $("event-dialog").showModal();
}

function field(list, label, raw) {
  const item = node("div", "", "definition-item");
  item.append(node("dt", label), node("dd", value(raw))); list.append(item);
}
function property(list, label, raw) {
  const item = node("div", "", "property-item");
  item.append(node("span", label, "property-label"), node("strong", value(raw), "property-value")); list.append(item);
}

function setReadStatus(element, state, message, busy = false) {
  element.dataset.state = state;
  if (element.textContent !== message) element.textContent = message;
  element.hidden = false;
  element.setAttribute("aria-busy", String(busy));
}
function hasReading(raw) { return raw !== null && raw !== undefined && raw !== ""; }
function detailReading(detail, kind, primary, fallback, phase) {
  const observed = detail.source_observed_at?.[kind];
  const age = Date.now() / 1000 - observed;
  const current = Boolean(detail.sources?.[kind]) && Number.isFinite(observed) && age >= -5 && age <= 120;
  if (hasReading(primary)) return {raw: primary, state: current ? "current" : "cached"};
  if (hasReading(fallback)) return {raw: fallback, state: "cached"};
  return {raw: "—", state: detail.sources?.[kind] ? "not-reported" : "unavailable"};
}
function markedField(list, label, reading, propertyStyle = false) {
  if (reading.state !== "current" && reading.state !== "cached") return;
  const item = node("div", "", propertyStyle ? "property-item" : "definition-item");
  const title = node(propertyStyle ? "span" : "dt", label, propertyStyle ? "property-label" : "");
  const content = node(propertyStyle ? "strong" : "dd", reading.raw,
    propertyStyle ? "property-value" : "");
  const marker = node("span", reading.state === "current" ? "Current" : "Last known", `read-marker ${reading.state}`);
  item.append(title, content, marker);
  list.append(item);
}

function renderDetails(server, detail, phase = "settled", cached = {}) {
  const system = detail.system || {};
  const manager = detail.manager || {};
  const oldSystem = cached.system || {};
  const oldChassis = cached.chassis || {};
  const oldManager = cached.manager || {};
  const missing = detail.unavailable || [];
  const status = $("detail-source-status");
  const observed = Object.keys(detail.sources || {}).map(kind => detail.source_observed_at?.[kind])
    .filter(stamp => Number.isFinite(stamp) && Date.now() / 1000 - stamp >= -5 && Date.now() / 1000 - stamp <= 120);
  const live = observed.length > 0;
  const timestamp = live ? Math.max(...observed) * 1000 : detail.checked_at || server.discovery?.checked_at;
  const hasLastKnown = detail.cached || Object.keys(system).length || Object.keys(manager).length || Object.keys(detail.chassis || {}).length;
  if (phase === "loading") setReadStatus(status, "loading", "Last-known details · refreshing in the background.", true);
  else if (phase === "error") setReadStatus(status, "error", `Could not refresh Redfish details. Showing last-known values where available${timestamp ? ` · last checked ${formatTime(timestamp)}` : ""}.`);
  else if (missing.length) setReadStatus(status, "partial", `Partially checked ${formatTime(detail.fetched_at)} · ${missing.join(", ")} unavailable. Last-known values are labeled below.`);
  else if (live) setReadStatus(status, "current", `Checked ${formatTime(detail.fetched_at)} · current and last-known fields are labeled below.`);
  else setReadStatus(status, hasLastKnown ? "cached" : "unavailable", `${detail.cached ? "Last-known inventory" : hasLastKnown ? "Last-known Redfish details" : "Redfish details unavailable"}${timestamp ? ` · last read ${formatTime(timestamp)}` : ""}.`);
  const fields = $("detail-fields"); fields.replaceChildren();
  field(fields, "Name", server.name); field(fields, "BMC endpoint", bmcEndpoint(server));
  for (const [label, kind, primary, fallback] of [
    ["Model", "system", system.Model, oldSystem.Model ?? server.discovery?.model],
    ["Manufacturer", "system", system.Manufacturer, oldSystem.Manufacturer ?? server.discovery?.manufacturer],
    ["Serial number", "system", system.SerialNumber, oldSystem.SerialNumber ?? server.discovery?.serial_number],
    ["UUID", "system", system.UUID, oldSystem.UUID], ["Asset tag", "system", system.AssetTag, oldSystem.AssetTag],
    ["BMC firmware", "manager", manager.FirmwareVersion, oldManager.FirmwareVersion ?? server.discovery?.firmware_version],
    ["BIOS version", "system", system.BiosVersion, oldSystem.BiosVersion ?? server.discovery?.bios_version],
  ]) markedField(fields, label, detailReading(detail, kind, primary, fallback, phase));
  const properties = $("detail-properties"); properties.replaceChildren();
  for (const [label, kind, primary, fallback] of [
    ["System health", "system", system.Status?.Health, oldSystem.Status?.Health ?? server.discovery?.system_status?.Health],
    ["Chassis health", "chassis", detail.chassis?.Status?.Health, oldChassis.Status?.Health],
    ["Power state", "system", system.PowerState, oldSystem.PowerState ?? server.discovery?.system_power_state],
    ["Processors", "system", system.ProcessorSummary?.Count, server.discovery?.processor_summary?.Count],
    ["Processor model", "system", system.ProcessorSummary?.Model, server.discovery?.processor_summary?.Model],
    ["Memory (GiB)", "system", system.MemorySummary?.TotalSystemMemoryGiB, server.discovery?.memory_summary?.TotalSystemMemoryGiB],
    ["Sensors", "thermal", null, server.discovery?.sensor_count],
  ]) markedField(properties, label, detailReading(detail, kind, primary, fallback, phase), true);
  const collectionList = $("detail-collection"); collectionList.replaceChildren();
  property(collectionList, "Exporter", server.exporter_running ? "Running" : "Stopped");
  property(collectionList, "Prometheus port", server.port);
  property(collectionList, "SSE endpoint", server.discovery?.events_sse ? "Advertised (not subscribed)" : "Not advertised");
  if (Object.keys(detail.sources || {}).length) property(collectionList, "Redfish resources", Object.keys(detail.sources).join(", "));
  if (missing.length) property(collectionList, "Unavailable now", missing.join(", "));
  show("detail-content", true);
}

async function loadDetailEvents(serverId) {
  const list = $("detail-event-list"); list.replaceChildren();
  try {
    const events = await api(`/api/events?server_id=${encodeURIComponent(serverId)}&limit=8`);
    if (!isGeneralRoute(serverId)) return;
    if (!events.length) { list.append(node("p", "No events collected for this server yet.", "muted")); return; }
    for (const event of events) {
      const item = node("div", "", "event-preview");
      item.append(badge(event.severity || "Event", event.severity === "Critical" ? "bad" : "neutral"),
                  node("span", event.message || "No message", "preview-message"),
                  node("time", formatTime(event.observed_at), "preview-time"));
      list.append(item);
    }
  } catch { if (isGeneralRoute(serverId)) list.append(node("p", "Recent events could not be loaded.", "muted")); }
}

async function showDetail(serverId) {
  const server = servers.find(item => item.id === serverId);
  if (!server) { location.hash = "#/servers"; say("Server not found."); return; }
  currentDetail = serverId;
  $("detail-name").textContent = server.name;
  updateDetailPowerIcon(server);
  $("detail-metrics-link").href = server.scrape_url;
  $("detail-actions").disabled = identity?.role !== "admin";
  const badges = $("detail-badges"); badges.replaceChildren(badge(...health(server)), badge(...collection(server)));
  if (!isGeneralRoute(serverId)) return;
  const request = ++generalRequest;
  $("detail-content").setAttribute("aria-busy", "true");
  let cachedDetail = {sources: {}, unavailable: []};
  renderDetails(server, cachedDetail, "loading");
  loadDetailEvents(serverId);
  try {
    // Local inventory supplies last-known fields that discovery does not keep
    // (for example UUID and chassis health), without initiating a BMC read.
    const inventory = await api(`/api/servers/${encodeURIComponent(serverId)}/inventory`);
    if (!isGeneralRoute(serverId) || request !== generalRequest) return;
    const categories = inventory.snapshot?.categories || {};
    const firstFields = name => categories[name]?.items?.[0]?.fields || {};
    cachedDetail = {system: firstFields("System"), chassis: firstFields("Chassis"),
      manager: firstFields("Management controllers"), sources: {}, unavailable: [],
      cached: true, checked_at: inventory.snapshot?.collected_at};
    renderDetails(server, cachedDetail, "loading");
  } catch { /* Discovery values remain available if inventory is absent. */ }
  try {
    while (isGeneralRoute(serverId) && request === generalRequest) {
      const detail = await api(`/api/servers/${encodeURIComponent(serverId)}/details`, "GET", null, 10000);
      if (!isGeneralRoute(serverId) || request !== generalRequest) return;
      if (detail.refreshing || detail.queued) {
        renderDetails(server, detail, "loading", cachedDetail);
        await new Promise(resolve => setTimeout(resolve, 2000));
        continue;
      }
      renderDetails(server, detail, detail.refresh_error ? "error" : "settled", cachedDetail);
      if (!detail.refresh_error) {
        await loadServers();
        if (!isGeneralRoute(serverId) || request !== generalRequest) return;
        const updated = servers.find(item => item.id === serverId);
        if (updated) badges.replaceChildren(badge(...health(updated)), badge(...collection(updated)));
      }
      break;
    }
  } catch (error) {
    if (isGeneralRoute(serverId) && request === generalRequest) {
      renderDetails(server, cachedDetail, "error");
    }
  } finally { if (isGeneralRoute(serverId) && request === generalRequest) $("detail-content").setAttribute("aria-busy", "false"); }
}

function isGeneralRoute(serverId) { return location.hash === `#/servers/${serverId}` && currentDetail === serverId; }

const inventoryLabels = {System: "System", Subsystems: "Subsystems", Chassis: "Chassis", "Management controllers": "Management controllers",
  Processors: "Processors", GPUs: "GPUs", FPGAs: "FPGAs", Memory: "Memory", Storage: "Storage", Controllers: "Storage controllers", Drives: "Drives", Volumes: "Volumes", BootOptions: "Boot options",
  NetworkInterfaces: "Host network interfaces", NetworkAdapters: "Network adapters", PCIeDevices: "PCIe devices",
  NetworkDeviceFunctions: "Network device functions", EthernetInterfaces: "Ethernet interfaces",
  PCIeFunctions: "PCIe functions", PowerSubsystem: "Power subsystem", PowerSupplies: "Power supplies", Fans: "Fans"};
const fieldLabels = {Id: "ID", UUID: "UUID", SKU: "SKU", BiosVersion: "BIOS version", CapacityMiB: "Capacity (MiB)", CapacityBytes: "Capacity (bytes)",
  OperatingSpeedMHz: "Operating speed (MHz)", OperatingSpeedMhz: "Operating speed (MHz)",
  AllowedSpeedsMHz: "Allowed speeds (MHz)", MaxSpeedMHz: "Maximum speed (MHz)",
  CurrentLinkSpeedMbps: "Current link speed (Mbps)", SpeedRPM: "Speed (RPM)", ReadingRPM: "Reading (RPM)",
  PowerCapacityWatts: "Power capacity (W)", MACAddress: "MAC address", PermanentMACAddress: "Permanent MAC address",
  FirmwarePackageVersion: "Controller firmware", AdapterModel: "Linked adapter model", AdapterManufacturer: "Linked adapter manufacturer",
  AdapterPartNumber: "Linked adapter part number", AdapterFirmwareVersion: "Linked adapter firmware",
  BootOptionReference: "Boot reference", BootOptionEnabled: "Enabled"};
const displayField = key => fieldLabels[key] || key.replace(/([a-z])([A-Z])/g, "$1 $2");
function inventoryText(raw, key = "") {
  if (raw === null || raw === undefined) return "";
  if (Array.isArray(raw)) return raw.map(item => inventoryText(item, key)).filter(Boolean).join(", ");
  if (typeof raw === "object") {
    if (typeof raw.PartLocation?.ServiceLabel === "string") return raw.PartLocation.ServiceLabel;
    if (typeof raw.Info === "string") return raw.Info;
    if (key === "PCIeInterface") {
      const generation = raw.PCIeType || raw.MaxPCIeType;
      const lanes = raw.LanesInUse ?? raw.MaxLanes;
      return [generation && `PCIe ${generation}`, Number.isFinite(lanes) && `x${lanes}`].filter(Boolean).join(" · ");
    }
    if (key === "Status" || typeof raw.Health === "string" || typeof raw.State === "string") {
      return [raw.Health || raw.HealthRollup, raw.State].filter(Boolean).join(" · ");
    }
    return Object.entries(raw).map(([name, item]) => {
      const formatted = inventoryText(item, name);
      return formatted ? `${displayField(name)}: ${formatted}` : "";
    }).filter(Boolean).join(" · ");
  }
  if (typeof raw === "number") return raw.toLocaleString();
  if (typeof raw === "boolean") return raw ? "Yes" : "No";
  const value = String(raw).trim();
  if (key === "LinkStatus" && /^Link(?:Up|Down)$/i.test(value)) return value.slice(4);
  return /^(?:n\/?a|nil)$/i.test(value) ? "" : value;
}
function inventorySpec(fields) {
  const parts = [];
  if (fields.ProcessorType && (inventoryText(fields.Model) || inventoryText(fields.AdapterModel))) parts.push(inventoryText(fields.ProcessorType));
  if (Number.isFinite(fields.CapacityMiB)) parts.push(`${Number(fields.CapacityMiB / 1024).toLocaleString(undefined, {maximumFractionDigits: 1})} GiB`);
  else if (Number.isFinite(fields.CapacityBytes)) parts.push(`${Number(fields.CapacityBytes / 1073741824).toLocaleString(undefined, {maximumFractionDigits: 1})} GiB`);
  if (Number.isFinite(fields.TotalCores)) parts.push(`${fields.TotalCores} cores`);
  if (Number.isFinite(fields.TotalThreads)) parts.push(`${fields.TotalThreads} threads`);
  if (fields.ProcessorType === "GPU" && Number.isFinite(fields.MaxSpeedMHz)) parts.push(`Max ${fields.MaxSpeedMHz} MHz`);
  else if (Number.isFinite(fields.OperatingSpeedMHz ?? fields.OperatingSpeedMhz)) parts.push(`${fields.OperatingSpeedMHz ?? fields.OperatingSpeedMhz} MHz`);
  if (Number.isFinite(fields.PowerCapacityWatts)) parts.push(`${fields.PowerCapacityWatts} W capacity`);
  if (Number.isFinite(fields.CurrentLinkSpeedMbps)) parts.push(`${fields.CurrentLinkSpeedMbps} Mbps`);
  if (Number.isFinite(fields.ReadingRPM ?? fields.SpeedRPM)) parts.push(`${fields.ReadingRPM ?? fields.SpeedRPM} RPM`);
  return parts.join(" · ");
}
function inventoryItemName(item, category = "") {
  const fields = item.fields || {};
  if (category === "PowerSubsystem" && fields.Id === "PowerSubsytem") return "Power subsystem";
  if (category === "GPUs" && fields.Location?.PartLocation?.ServiceLabel) return inventoryText(fields.Location.PartLocation.ServiceLabel);
  if (category === "BootOptions") return inventoryText(fields.DisplayName || fields.Description || fields.BootOptionReference || fields.Id);
  if (category === "Processors" || category === "FPGAs") return inventoryText(fields.Id || fields.Name || item.source?.split("/").pop());
  return inventoryText(fields.Name || fields.Id || item.source?.split("/").pop() || "Component");
}
const inventoryOrder = ["System", "BootOptions", "Subsystems", "Processors", "GPUs", "FPGAs", "Memory", "Chassis", "Storage", "Controllers", "Drives", "Volumes", "NetworkAdapters", "NetworkInterfaces", "EthernetInterfaces", "NetworkDeviceFunctions", "PCIeDevices", "PCIeFunctions", "PowerSubsystem", "PowerSupplies", "Fans", "Management controllers"];
const naturalInventory = (a, b, category) => inventoryItemName(a, category).localeCompare(inventoryItemName(b, category), undefined,
  {numeric: !["PCIeDevices", "PCIeFunctions"].includes(category), sensitivity: "base"});
function bootOrder() { return inventorySnapshot?.snapshot?.categories?.System?.items?.[0]?.fields?.Boot?.BootOrder || []; }
function sortedInventoryItems(items, category) {
  const result = [...items];
  if (category === "BootOptions") {
    const order = bootOrder();
    result.sort((a, b) => {
      const ai = order.indexOf(a.fields?.BootOptionReference), bi = order.indexOf(b.fields?.BootOptionReference);
      return (ai < 0 ? Infinity : ai) - (bi < 0 ? Infinity : bi) || naturalInventory(a, b, category);
    });
  } else result.sort((a, b) => naturalInventory(a, b, category));
  return result;
}
function renderInventoryStatus(state, available) {
  const checkedAt = state.last_success_at ? `Last checked ${formatTime(state.last_success_at)}` : "No completed check yet";
  const failed = state.state === "failed" || state.state === "interrupted" || state.state === "partial";
  const firstBuild = !available && !state.last_success_at && (state.running || state.state === "pending");
  const message = firstBuild ? (state.running ? "Building the first inventory snapshot…" : "Preparing the first inventory snapshot…") :
    state.running ? `Checking inventory… · ${checkedAt}` :
    !available ? `Inventory unavailable · ${checkedAt}` :
    state.state === "partial" ? `Inventory incomplete · ${checkedAt}` :
    state.state === "interrupted" ? `Latest check interrupted · ${checkedAt}` :
    failed ? `Latest check failed · ${checkedAt}` : checkedAt;
  setReadStatus($("inventory-status"), firstBuild || state.running ? "loading" : !available ? "unavailable" :
    failed ? "error" : "cached", message, state.running);
  $("detail-inventory").setAttribute("aria-busy", String(Boolean(state.running)));
  $("inventory-refresh").disabled = state.running;
  show("inventory-feedback", !available);
  $("inventory-retry").hidden = firstBuild;
  if (!available) $("inventory-feedback-text").textContent = firstBuild ? (state.running ?
    "Building this server's first inventory snapshot. This can take several minutes; you can leave this page and it will update automatically." :
    "The first inventory collection starts automatically after onboarding. You can leave this page and return when it is ready.") :
    "No inventory snapshot is available. Retry this view, or refresh inventory as an admin.";
}
function renderInventory() {
  const state = inventorySnapshot;
  if (!state) return;
  const categories = state.snapshot?.categories || {};
  const names = Object.keys(categories).filter(name => categories[name]?.items?.length)
    .sort((a, b) => (inventoryOrder.indexOf(a) < 0 ? 999 : inventoryOrder.indexOf(a)) -
      (inventoryOrder.indexOf(b) < 0 ? 999 : inventoryOrder.indexOf(b)) || a.localeCompare(b));
  if (categories.Controllers?.items?.length && categories["Storage controllers"]?.items?.length) {
    // Older saved snapshots contain the same storage controllers both as
    // linked resources and embedded objects. Prefer the linked resources.
    const duplicate = names.indexOf("Storage controllers");
    if (duplicate >= 0) names.splice(duplicate, 1);
  }
  // A host NetworkInterface on this BMC has no independent hardware identity;
  // its linked NetworkAdapter is the useful, provenance-backed asset.
  if (categories.NetworkAdapters?.items?.length && categories.NetworkInterfaces?.items?.length &&
      categories.NetworkInterfaces.items.every(item => item.adapter_source)) {
    const redundant = names.indexOf("NetworkInterfaces");
    if (redundant >= 0) names.splice(redundant, 1);
  }
  if (!names.includes(inventoryCategory)) {
    inventoryCategory = names[0] || null;
    if (inventoryCategory) inventoryExpanded.add(inventoryCategory);
  }
  const selected = categories[inventoryCategory]?.items?.find(item => item.source === inventorySelectedSource) || null;
  if (!selected) inventorySelectedSource = null;
  inventoryExpanded = new Set([...inventoryExpanded].filter(name => names.includes(name)));
  const available = Boolean(names.length);
  renderInventoryStatus(state, available);
  const nav = $("inventory-categories"); nav.replaceChildren();
  if (!names.length) nav.append(node("p", "No asset components collected yet.", "empty-state"));
  if (names.length) {
    const allExpanded = names.every(name => inventoryExpanded.has(name));
    const toggleAll = node("button", allExpanded ? "Collapse all" : "Expand all", "inventory-expand-all");
    toggleAll.type = "button";
    toggleAll.addEventListener("click", () => {
      inventoryExpanded = allExpanded ? new Set() : new Set(names);
      renderInventory();
    });
    nav.append(toggleAll);
  }
  for (const name of names) {
    const categoryItems = sortedInventoryItems(categories[name].items, name);
    const group = node("div", "", "inventory-category-group");
    const expanded = inventoryExpanded.has(name);
    const button = node("button", "", "inventory-category");
    button.type = "button"; button.classList.toggle("active", name === inventoryCategory);
    button.setAttribute("aria-expanded", String(expanded));
    button.append(node("span", expanded ? "⌄" : "›", "inventory-chevron"),
                  node("span", inventoryLabels[name] || displayField(name), "inventory-category-name"),
                  node("span", categories[name].items.length, "inventory-category-count"));
    button.addEventListener("click", () => {
      if (inventoryCategory === name && inventorySelectedSource) inventoryExpanded.add(name);
      else if (expanded) inventoryExpanded.delete(name); else inventoryExpanded.add(name);
      if (inventoryCategory !== name) {
        inventoryCategory = name; inventoryPage = 0;
        $("inventory-search").value = "";
      }
      inventorySelectedSource = null;
      renderInventory();
    });
    group.append(button);
    if (expanded) {
      const children = node("div", "", "inventory-children");
      for (const item of categoryItems) {
        const child = node("button", "", "inventory-child");
        child.type = "button";
        child.title = inventoryItemName(item, name);
        child.classList.toggle("active", inventoryCategory === name && inventorySelectedSource === item.source);
        const reportedHealth = item.fields?.Status?.Health || item.fields?.Status?.HealthRollup;
        child.append(node("span", "", "inventory-branch"), node("span", inventoryItemName(item, name), "inventory-child-name"));
        if (reportedHealth) child.append(node("span", reportedHealth, `inventory-child-health ${reportedHealth === "OK" ? "good" : reportedHealth === "Warning" ? "warn" : reportedHealth === "Critical" ? "bad" : "neutral"}`));
        child.addEventListener("click", () => {
          inventoryCategory = name;
          inventorySelectedSource = item.source;
          inventoryPage = Math.floor(categoryItems.indexOf(item) / 50);
          $("inventory-search").value = "";
          renderInventory();
        });
        children.append(child);
      }
      group.append(children);
    }
    nav.append(group);
  }
  const items = sortedInventoryItems(categories[inventoryCategory]?.items || [], inventoryCategory);
  show("inventory-back", Boolean(selected));
  show("inventory-search-label", !selected && available);
  show("inventory-table", !selected && available);
  show("inventory-pager", !selected && available);
  if (selected) {
    $("inventory-category-title").textContent = inventoryItemName(selected, inventoryCategory);
    $("inventory-count").textContent = inventoryLabels[inventoryCategory] || displayField(inventoryCategory);
    showInventoryItem(selected);
    return;
  }
  show("inventory-detail", false);
  const query = $("inventory-search").value.trim().toLowerCase();
  const shown = query ? items.filter(item => Object.values(item.fields || {}).some(raw => inventoryText(raw).toLowerCase().includes(query))) : items;
  const maxPage = Math.max(0, Math.ceil(shown.length / 50) - 1);
  inventoryPage = Math.min(inventoryPage, maxPage);
  $("inventory-category-title").textContent = inventoryLabels[inventoryCategory] || (inventoryCategory ? displayField(inventoryCategory) : "Inventory");
  $("inventory-count").textContent = `${shown.length} ${shown.length === 1 ? "component" : "components"}`;
  const table = $("inventory-table"); table.replaceChildren();
  if (shown.length) {
    const element = node("table", "", "data-table inventory-table");
    const header = node("thead"); const headings = node("tr");
    const bootCategory = inventoryCategory === "BootOptions";
    const anyField = getter => shown.some(item => Boolean(inventoryText(getter(item.fields || {}))));
    const firstReported = (...values) => values.find(value => inventoryText(value)) || "";
    const model = fields => firstReported(fields.Model, fields.AdapterModel, fields.ProcessorType, fields.MemoryDeviceType, fields.MemoryType);
    const firmware = fields => firstReported(fields.FirmwareVersion, fields.FirmwarePackageVersion, fields.AdapterFirmwareVersion, fields.BiosVersion);
    const columns = bootCategory ? ["Order", "Boot option", "Reference", "Enabled"] : ["Component"];
    if (!bootCategory) {
      if (anyField(model)) columns.push("Model / type");
      if (anyField(inventorySpec)) columns.push("Specification");
      if (inventoryCategory === "EthernetInterfaces" && anyField(fields => fields.MACAddress)) columns.push("MAC address");
      if (inventoryCategory === "EthernetInterfaces" && anyField(fields => fields.LinkStatus)) columns.push("Link");
      if (anyField(firmware)) columns.push("Firmware");
      if (anyField(fields => fields.SerialNumber)) columns.push("Serial number");
      if (anyField(fields => fields.Status?.Health || fields.Status?.HealthRollup || fields.Status?.State)) columns.push("Health / state");
    }
    for (const label of columns) headings.append(node("th", label));
    header.append(headings); element.append(header);
    const body = node("tbody");
    for (const item of shown.slice(inventoryPage * 50, inventoryPage * 50 + 50)) {
      const fields = item.fields || {}; const row = node("tr");
      if (bootCategory) {
        const position = bootOrder().indexOf(fields.BootOptionReference);
        row.append(node("td", position >= 0 ? String(position + 1) : ""));
      }
      const name = node("td"); const open = node("button", inventoryItemName(item, inventoryCategory), "text-button");
      open.type = "button"; open.addEventListener("click", () => {
        inventorySelectedSource = item.source; inventoryExpanded.add(inventoryCategory);
        renderInventory();
      }); name.append(open);
      row.append(name);
      if (bootCategory) {
        row.append(node("td", inventoryText(fields.BootOptionReference)));
        row.append(node("td", inventoryText(fields.BootOptionEnabled)));
        body.append(row);
        continue;
      }
      if (columns.includes("Model / type")) row.append(node("td", inventoryText(model(fields))));
      if (columns.includes("Specification")) row.append(node("td", inventorySpec(fields), "inventory-spec"));
      if (columns.includes("MAC address")) row.append(node("td", inventoryText(fields.MACAddress), "mono"));
      if (columns.includes("Link")) row.append(node("td", inventoryText(fields.LinkStatus, "LinkStatus")));
      if (columns.includes("Firmware")) row.append(node("td", inventoryText(firmware(fields))));
      if (columns.includes("Serial number")) row.append(node("td", inventoryText(fields.SerialNumber)));
      const statusCell = node("td");
      const status = fields.Status;
      if (status && typeof status === "object") {
        const health = status.Health || status.HealthRollup;
        if (health) statusCell.append(badge(health, health === "OK" ? "good" : health === "Warning" ? "warn" : health === "Critical" ? "bad" : "neutral"));
        if (status.State) statusCell.append(node("span", status.State, "inventory-state"));
      }
      if (columns.includes("Health / state")) {
        if (!statusCell.textContent) statusCell.append(node("span", "Not reported", "muted"));
        row.append(statusCell);
      }
      body.append(row);
    }
    element.append(body); table.append(element);
  } else table.append(node("p", "No components match this category and search.", "empty-state"));
  renderPageNumbers("inventory-page-numbers", shown.length ? inventoryPage + 1 : 0, shown.length ? maxPage + 1 : 0,
    number => { inventoryPage = number - 1; renderInventory(); }, "inventory");
  $("inventory-prev").disabled = inventoryPage === 0;
  $("inventory-next").disabled = inventoryPage >= maxPage;
}
function showInventoryItem(item) {
  const box = $("inventory-detail"); box.replaceChildren();
  const facts = node("dl", "", "inventory-facts");
  if (inventoryCategory === "BootOptions") {
    const position = bootOrder().indexOf(item.fields?.BootOptionReference);
    if (position >= 0) { const order = node("div"); order.append(node("dt", "Boot order"), node("dd", String(position + 1))); facts.append(order); }
  }
  for (const [key, raw] of Object.entries(item.fields || {})) {
    if (key === "Boot" || key === "Links") continue;
    if (inventoryCategory === "PowerSubsystem" && ["Name", "Description"].includes(key) && typeof raw === "string" && raw.startsWith("PowerSubsytem")) continue;
    if (inventoryCategory === "GPUs" && (key === "OperatingSpeedMHz" || (key === "Name" && raw === "Processor"))) continue;
    if (inventoryCategory === "BootOptions" && ["Id", "Name", "Description", "DisplayName"].includes(key)) continue;
    const formatted = inventoryText(raw, key);
    if (!formatted) continue;
    const fact = node("div"); fact.append(node("dt", displayField(key)), node("dd", formatted)); facts.append(fact);
  }
  const source = node("div"); source.append(node("dt", "Redfish source"), node("dd", item.source)); facts.append(source);
  if (item.adapter_source) { const linked = node("div"); linked.append(node("dt", "Linked network adapter source"), node("dd", item.adapter_source)); facts.append(linked); }
  box.append(facts);
  const boot = item.fields?.Boot;
  if (boot && typeof boot === "object") {
    const section = node("section", "", "inventory-boot"); section.append(node("h3", "Boot configuration"));
    const options = inventorySnapshot?.snapshot?.categories?.BootOptions?.items || [];
    const optionNames = new Map(options.map(option => [option.fields?.BootOptionReference,
      option.fields?.DisplayName || option.fields?.Description || option.fields?.Name]));
    if (Array.isArray(boot.BootOrder) && boot.BootOrder.length) {
      section.append(node("h4", "Boot order"));
      const list = node("ol");
      for (const reference of boot.BootOrder) {
        const name = optionNames.get(reference);
        list.append(node("li", name && name !== reference ? `${name} (${reference})` : reference));
      }
      section.append(list);
    }
    const override = [boot.BootSourceOverrideTarget && `Target: ${boot.BootSourceOverrideTarget}`,
      boot.BootSourceOverrideEnabled && `State: ${boot.BootSourceOverrideEnabled}`,
      boot.BootSourceOverrideMode && `Mode: ${boot.BootSourceOverrideMode}`].filter(Boolean);
    if (override.length) section.append(node("p", `Boot override · ${override.join(" · ")}`, "muted"));
    box.append(section);
  }
  show("inventory-detail", true);
}
async function loadInventory(serverId) {
  const request = ++inventoryRequest;
  const active = () => request === inventoryRequest && location.hash === `#/servers/${serverId}/inventory` && identity;
  $("detail-inventory").setAttribute("aria-busy", "true");
  if (inventorySnapshot) setReadStatus($("inventory-status"), "loading", `Checking inventory…${inventorySnapshot.last_success_at ? ` · Last checked ${formatTime(inventorySnapshot.last_success_at)}` : ""}`, true);
  else {
    setReadStatus($("inventory-status"), "loading", "Checking inventory…", true);
    $("inventory-feedback-text").textContent = "Loading this server's inventory…";
    show("inventory-feedback", true);
  }
  try {
    const revision = inventorySnapshot && inventoryServerId === serverId && Number.isInteger(inventorySnapshot.revision)
      ? `?since=${inventorySnapshot.revision}` : "";
    const state = await api(`/api/servers/${encodeURIComponent(serverId)}/inventory${revision}`, "GET", null, 15000);
    if (!active()) return;
    if (state.unchanged && inventorySnapshot) state.snapshot = inventorySnapshot.snapshot;
    const signature = Number.isInteger(state.revision) ? String(state.revision) :
      JSON.stringify([state.snapshot, state.state, state.running, state.last_success_at]);
    inventorySnapshot = state;
    if (signature !== inventorySignature) { inventorySignature = signature; renderInventory(); }
    else renderInventoryStatus(state, Boolean(Object.values(state.snapshot?.categories || {}).some(category => category?.items?.length)));
  } catch {
    if (!active()) return;
    $("detail-inventory").setAttribute("aria-busy", "false");
    setReadStatus($("inventory-status"), "error", inventorySnapshot?.last_success_at ?
      `Could not load inventory status · Last checked ${formatTime(inventorySnapshot.last_success_at)}` :
      "Inventory is unavailable. Retry this view.");
    $("inventory-feedback-text").textContent = inventorySnapshot ?
      "Could not load the latest inventory status. Available components remain visible." : "Inventory could not be loaded.";
    show("inventory-feedback", true);
  }
}

function renderDeploymentImpact() {
  const form = $("deployment-form");
  const bind = form.elements.namedItem("bind_address").value;
  const preview = $("deployment-impact-preview");
  preview.hidden = !bind || bind === "::1" || bind.startsWith("127.");
  preview.textContent = preview.hidden ? "" :
    "External interface: manager, exporters, and consoles will be reachable on this address.";
  const advertised = form.elements.namedItem("advertised_dns_name").value.trim() || bind;
  const managerPort = Number(form.elements.namedItem("manager_port").value);
  const first = Number(form.elements.namedItem("port_start").value);
  const last = Number(form.elements.namedItem("port_end").value);
  const offset = Number(form.elements.namedItem("console_port_offset").value);
  const connection = $("deployment-preview");
  connection.hidden = !bind || !Number.isInteger(managerPort) || managerPort < 1 || managerPort > 65535 ||
    !Number.isInteger(first) || first < 1 || !Number.isInteger(last) || last < first || last > 65535 ||
    !form.elements.namedItem("console_port_offset").value || !Number.isInteger(offset) ||
    first + offset < 1 || last + offset > 65535 ||
    (advertised !== bind && !/^[A-Za-z0-9.-]+$/.test(advertised));
  const facts = $("deployment-preview-facts");
  facts.replaceChildren();
  if (connection.hidden) return;
  const host = advertised.includes(":") ? `[${advertised}]` : advertised;
  for (const [label, value] of [
    ["Manager", `https://${host}:${managerPort}/`],
    ["Exporters", `https://${host}:<port>/metrics · ${first}–${last}`],
    ["Consoles", `${first + offset}–${last + offset}`],
  ]) {
    const item = node("div", "", "config-fact");
    item.append(node("strong", label), node("span", value));
    facts.append(item);
  }
}

async function loadConfiguration() {
  if (identity?.role !== "admin") return;
  const data = await api("/api/configuration");
  if (!/^#\/configuration\/(collection|console|users|application|security|backup)$/.test(location.hash)) return;
  const form = $("collection-settings-form");
  for (const [key, number] of Object.entries(data.collection)) form.elements.namedItem(key).value = number;
  $("console-settings-form").elements.namedItem("idle_minutes").value = data.console.idle_minutes;
  $("login-settings-form").elements.namedItem("login_idle_minutes").value = data.console.login_idle_minutes;
  const deploymentForm = $("deployment-form");
  const bindSelect = deploymentForm.elements.namedItem("bind_address"); bindSelect.replaceChildren();
  const interfaces = data.local_interfaces || (data.local_addresses || []).map(address => ({interface: "Local", address}));
  for (const item of interfaces) {
    const option = node("option", `${item.interface} · ${item.address}`);
    option.value = item.address; bindSelect.append(option);
  }
  const replacement = $("restore-preview-form").elements.namedItem("replacement_address");
  const selectedReplacement = replacement.value;
  replacement.replaceChildren();
  const archived = node("option", "Use archived address"); archived.value = ""; replacement.append(archived);
  for (const item of data.local_interfaces || []) {
    const option = node("option", `${item.interface} · ${item.address}`);
    option.value = item.address; replacement.append(option);
  }
  if ([...replacement.options].some(option => option.value === selectedReplacement))
    replacement.value = selectedReplacement;
  if (!restoreCommitLocked && (restoreReview || restorePreviewController) && replacement.value !== selectedReplacement)
    clearRestoreReview("Preview cleared because the selected replacement address is no longer available. Validate the archive again.");
  for (const [key, value] of Object.entries(data.deployment || {})) {
    const field = deploymentForm.elements.namedItem(key);
    if (field && field.type !== "checkbox") field.value = value;
  }
  const existing = data.deployment || {};
  bindSelect.value = existing.manager_bind || "";
  const sharedBind = existing.manager_bind === existing.exporter_bind && existing.manager_bind === existing.console_bind;
  const sharedHost = existing.manager_host === existing.exporter_host && existing.manager_host === existing.console_host;
  const dnsHost = sharedHost && existing.manager_host && !existing.manager_host.includes(":") &&
    !/^\d+\.\d+\.\d+\.\d+$/.test(existing.manager_host) ? existing.manager_host : "";
  deploymentForm.elements.namedItem("advertised_dns_name").value = dnsHost;
  $("deployment-address-note").hidden = sharedBind && sharedHost;
  $("deployment-address-note").textContent = sharedBind && sharedHost ? "" :
    "Current listeners differ. Applying will use this shared address.";
  $("certificate-legacy-host-note").hidden = sharedHost;
  renderDeploymentImpact();
  const expiryMs = Date.parse(data.certificate?.expires_at || "");
  const certificateLabel = data.certificate?.source === "installation-generated" ? "Installation-generated" : "Operator-provided";
  let expiryLabel = "Expiry unavailable";
  if (Number.isFinite(expiryMs)) {
    const date = new Date(expiryMs).toISOString().slice(0, 10);
    const daysLeft = Math.ceil((expiryMs - Date.now()) / 86400000);
    expiryLabel = daysLeft <= 0 ? `Expired ${date} UTC` :
      daysLeft <= 30 ? `Expires soon ${date} UTC (${daysLeft} days left)` :
      `Expires ${date} UTC (${daysLeft} days left)`;
  }
  $("certificate-status").textContent = data.certificate ?
    `Current certificate · ${certificateLabel} · ${expiryLabel}` : "Certificate status unavailable";
  $("certificate-trust-note").textContent = data.certificate?.source === "installation-generated" ?
    "Self-signed · trust its public certificate in browsers." :
    "Browsers must trust the issuing CA.";
  $("bmc-ca-status").textContent = data.bmc_ca_configured ? "Custom BMC CA bundle configured" : "Using system BMC trust";
  $("bmc-ca-clear").hidden = !data.bmc_ca_configured;
  deploymentLastAt = Math.max(deploymentLastAt, Number(data.deployment_last?.at || 0));
  $("deployment-result").textContent = data.deployment_last?.status === "unconfirmed" ?
    "HTTPS and Prometheus recovery is unconfirmed. Keep recovery files and check service status." :
    data.deployment_pending ? "Deployment restart in progress…" :
    data.deployment_last?.status === "reverted" ? `Last deployment failed: ${data.deployment_last.reason || "the proposed listener was unavailable"}. The previous HTTPS configuration was restored.` :
    data.deployment_last?.status === "applied" ? (data.deployment_last.reason || "Last deployment restart succeeded.") : "";
  const targets = $("config-targets"); targets.replaceChildren();
  for (const target of data.targets || []) {
    const server = servers.find(item => item.id === target.id);
    if (!server) continue;
    const row = node("div", "", "config-target");
    const identity = node("div", "", "config-target-identity");
    identity.append(node("strong", server.name), node("small", `${bmcEndpoint(target)} · BMC TLS certificate ${target.insecure_bmc ? "not verified (onboarding exception)" : "verified"}`));
    row.append(identity);
    const interval = node("label", "Inventory interval override (seconds) "); const input = node("input"); input.type = "number"; input.min = "300"; input.max = "86400"; input.placeholder = "Fleet default";
    input.value = target.inventory_interval_override ?? "";
    const save = node("button", "Save override", "button outline"); save.type = "button";
    save.addEventListener("click", async () => { try { await api(`/api/servers/${server.id}/inventory/interval`, "PATCH", {seconds: input.value ? Number(input.value) : null}); say("Inventory interval override saved; effective for the next schedule."); } catch (error) { say(error.message); } });
    interval.append(input); row.append(interval, save); targets.append(row);
  }
  const collectionFacts = $("config-collection-facts"); collectionFacts.replaceChildren();
  const deploymentFacts = $("config-deployment-facts"); deploymentFacts.replaceChildren();
  const labels = {event_poll_without_sse_seconds: "Log polling without SSE", event_poll_with_sse_seconds: "Log reconciliation with SSE",
    metric_retention_hours: "Local metric retention",
    manager_origin: "Manager origin", manager_bind: "Manager bind address", manager_port: "Manager port",
    exporter_bind: "Exporter bind address",
    exporter_advertise_host: "Exporter advertised host", exporter_port_range: "Exporter port range",
    exporter_tls: "Exporter HTTPS", console_bind: "Console bind address",
    console_advertise_host: "Console advertised host", console_port_offset: "Console port offset",
    console_tls: "Console HTTPS", bmc_ca: "BMC CA bundle"};
  for (const [key, number] of Object.entries(data.fixed)) {
    const units = key.endsWith("_seconds") ? "seconds" : key.endsWith("_hours") ? "hours" : "minutes";
    const fact = node("div", "", "config-fact"); fact.append(node("strong", labels[key] || key), node("span", `${number} ${units}`), node("small", "Currently fixed"));
    collectionFacts.append(fact);
  }
  for (const [key, setting] of Object.entries(data.restart_required)) {
    const fact = node("div", "", "config-fact"); fact.append(node("strong", labels[key] || key), node("span", setting), node("small", "Effective after latest supervised start")); deploymentFacts.append(fact);
  }
  const runtime = await api("/api/runtime");
  $("restart-open").disabled = !runtime.supervised;
  $("restart-availability").hidden = runtime.supervised;
  $("restart-availability").textContent = runtime.supervised ?
    "" : "Restart requires the manager supervisor.";
  const restoreState = await api("/api/backup/last");
  if (restoreState.last?.status === "unconfirmed" && !restoreUnknownContext) {
    restoreUnknownContext = {current: restoreState.last.current_url || location.origin,
      proposed: restoreState.last.result_url || location.origin, priorLastId: "", startedAt: Date.now()};
  }
  setRestorePreviewLocked(Boolean(restoreState.pending?.id || restoreUnknownContext || restoreState.last?.status === "unconfirmed"));
  if (restoreState.pending?.id) {
    restoreReview = null;
    $("restore-commit-form").hidden = true;
  }
  const lastRestore = restoreState.last;
  if (lastRestore?.id) restoreLastOperationId = lastRestore.id;
  const pendingPhase = {queued: "Queued", applying: "Applying", "checking-https": "Checking HTTPS"}[
    restoreState.pending?.status] || restoreState.pending?.status;
  $("restore-operation-status").textContent = restoreState.pending?.id ?
    `Restore ${restoreState.pending.id} · ${pendingPhase}. Wait for the result before retrying.` :
    lastRestore?.id ? restoreOutcomeMessage(lastRestore) :
      "No restore yet.";
  if (restoreState.pending?.id) appendRestoreAddress($("restore-operation-status"),
    restoreState.pending.result_url, "Try the proposed HTTPS address after restart");
  else if (lastRestore?.id) appendRestoreAddress($("restore-operation-status"),
    lastRestore.status === "applied" ? lastRestore.result_url : lastRestore.current_url,
    lastRestore.status === "applied" ? "Open the restored manager" : "Open the previous manager");
  if (restoreState.pending?.id && !restorePollTimer)
    pollRestoreResult(restoreState.pending.id,
      restoreState.pending.current_url || location.origin,
      restoreState.pending.result_url || location.origin);
  $("restore-check-status").hidden = !restoreUnknownContext;
  if (restoreUnknownContext && !restoreState.pending?.id) recoverUnconfirmedRestore();
  void resumeBackupPreparation();
  await loadUsers();
}

function configError(id, message = "") {
  const element = $(id);
  element.textContent = message;
  if (message) element.focus();
}

function deploymentMessage(id, text, reconnectUrl = "") {
  const element = $(id);
  element.replaceChildren(node("span", text));
  if (reconnectUrl) {
    const link = node("a", "Open the proposed HTTPS manager address");
    link.href = reconnectUrl;
    element.append(" ", link);
  }
}

async function watchDeployment(id, previousAt, reconnectUrl = "", onApplied = null) {
  deploymentWatchers++;
  try {
  deploymentMessage(id, "Restart accepted. HTTPS listeners are reconnecting; the supervisor will apply or restore the prior configuration.", reconnectUrl);
  for (let attempt = 0; attempt < 120; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    if (!identity) return;
    try {
      const data = await api("/api/configuration", "GET", null, 2500);
      if (data.deployment_last?.status === "unconfirmed" && Number(data.deployment_last.at || 0) > previousAt) {
        deploymentMessage(id, "HTTPS and Prometheus recovery is unconfirmed. Keep recovery files and check service status.");
        return;
      }
      if (data.deployment_pending || Number(data.deployment_last?.at || 0) <= previousAt) continue;
      if (data.deployment_last.status === "applied") {
        deploymentMessage(id, `${data.deployment_last.reason || "HTTPS restart succeeded."} Verify browser trust.`, reconnectUrl);
        if (onApplied) onApplied();
      } else {
        deploymentMessage(id, `Restart failed: ${data.deployment_last.reason || "the proposed listener was unavailable"}. The previous HTTPS configuration was restored; reconnect to the prior address.`);
      }
      try { await loadConfiguration(); } catch { /* The result above remains visible. */ }
      return;
    } catch { /* A stopped listener or new certificate can interrupt this check. */ }
  }
  deploymentMessage(id, "Could not confirm the restart from this page. Reconnect and check Deployment details for applied or reverted status.", reconnectUrl);
  } finally { deploymentWatchers--; }
}

async function loadUsers() {
  if (identity?.role !== "admin") return;
  const users = await api("/api/users");
  const list = $("config-users"); list.replaceChildren();
  for (const user of users) {
    const row = node("div", "", "user-row");
    const label = node("div", "", "user-identity");
    label.append(node("strong", user.username), node("small", user.disabled ? "Disabled" : "Active"));
    const role = node("select"); role.setAttribute("aria-label", `Role for ${user.username}`);
    role.add(new Option("Admin", "admin")); role.add(new Option("Read-only", "read-only")); role.value = user.role;
    const disabled = node("label", "Disabled "); const check = node("input"); check.type = "checkbox"; check.checked = Boolean(user.disabled); disabled.append(check);
    const save = node("button", "Save", "button outline"); save.type = "button";
    const password = node("button", "Change password", "button outline"); password.type = "button";
    const remove = node("button", "Delete", "button danger-link"); remove.type = "button";
    if (user.username === "admin") { role.disabled = true; check.disabled = true; remove.disabled = true; remove.title = "The bootstrap admin cannot be deleted or disabled"; }
    save.disabled = user.username === "admin";
    save.addEventListener("click", async () => {
      try { await api(`/api/users/${user.id}`, "PATCH", {role: role.value, disabled: check.checked}); say(`${user.username} updated. Existing sessions were revoked.`); await loadUsers(); }
      catch (error) { say(error.message); await loadUsers(); }
    });
    password.addEventListener("click", async () => {
      passwordUser = user;
      $("user-password-title").textContent = `Change password · ${user.username}`;
      $("user-password-form").reset();
      show("user-password-error", false);
      $("user-password-form").elements.namedItem("confirmation").removeAttribute("aria-invalid");
      $("user-password-dialog").showModal();
      $("user-password-form").elements.namedItem("password").focus();
    });
    remove.addEventListener("click", async () => {
      if (!confirm(`Delete local user ${user.username}? This will end their sessions.`)) return;
      try { await api(`/api/users/${user.id}`, "DELETE"); say(`${user.username} deleted.`); await loadUsers(); }
      catch (error) { say(error.message); }
    });
    row.append(label, role, disabled, save, password, remove); list.append(row);
  }
}

function applyRole(session) {
  identity = session;
  $("identity").textContent = `${session.username} · ${session.role === "admin" ? "Admin" : "Read-only"}`;
  show("account-menu", true);
  const admin = session.role === "admin";
  show("configuration-heading", admin);
  show("configuration-nav", admin);
  show("open-onboard", admin);
  show("inventory-refresh", admin);
  $("detail-actions").disabled = !admin;
  show("metrics-refresh", admin);
  show("detail-metrics-link", admin);
  show("host-resources", true);
  renderServers();
}

function showInitialPassword(session) {
  identity = session;
  show("dashboard", false);
  show("auth-shell", true);
  show("bootstrap", false);
  show("login", false);
  show("initial-password", true);
  say("");
  $("initial-password-form").elements.namedItem("password").focus();
}

function showLogin(message, broadcast = true) {
  if ($("connection-dialog").open) $("connection-dialog").close();
  document.body.classList.remove("connection-lost");
  connectionLost = false;
  connectionFailures = 0;
  const hadSession = Boolean(identity);
  authEpoch++;
  if (restorePollTimer) clearTimeout(restorePollTimer);
  restorePollTimer = null;
  backupAbortController?.abort();
  restorePreviewRevision++;
  restorePreviewController?.abort();
  restorePreviewController = null;
  setRestorePreviewLocked(false);
  restoreUnknownContext = null;
  $("restore-check-status").hidden = true;
  $("restore-preview-cancel").hidden = true;
  $("restore-preview-form").removeAttribute("aria-busy");
  restoreReview = null;
  $("restore-preview-form").reset();
  $("restore-commit-form").reset();
  $("restore-commit-form").hidden = true;
  $("restore-preview-result").replaceChildren();
  $("restore-preview-status").textContent = "";
  $("backup-form").reset();
  $("backup-result").replaceChildren();
  $("backup-error").textContent = "";
  lastSidebarRoute = null;
  prometheusView.reset();
  csrf = ""; identity = null; passwordUser = null; servers = []; currentDetail = null;
  onboardingJobs = []; onboardingJobStates.clear(); renderOnboardingJobs();
  for (const facet of FleetView.FACETS) fleetSelections[facet.key] = null;
  fleetPage = 1;
  $("server-search").value = "";
  $("fleet-page-size").value = "10";
  inventorySnapshot = null; inventoryServerId = null; inventorySignature = ""; inventorySelectedSource = null; currentMetric = null; metricsServerId = null; liveRenderedServerId = null;
  inventoryRequest++; catalogRequest++; chartRequest++; generalRequest++; liveRequest++;
  liveReadings.clear();
  liveSignatures.clear();
  for (const timer of liveRefreshTimers.values()) clearTimeout(timer);
  liveRefreshTimers.clear();
  if ($("metric-drawer").open) $("metric-drawer").close();
  if ($("onboard-dialog").open) $("onboard-dialog").close();
  if ($("user-password-dialog").open) $("user-password-dialog").close();
  if ($("unclaim-dialog").open) $("unclaim-dialog").close();
  if ($("restart-dialog").open) $("restart-dialog").close();
  if ($("server-action-confirm-dialog").open) $("server-action-confirm-dialog").close();
  if (actionsMenu.matches(":popover-open")) actionsMenu.hidePopover();
  for (const id of ["server-list", "fleet-summary", "event-list", "detail-fields", "detail-properties",
    "detail-collection", "detail-event-list", "inventory-categories", "inventory-table",
    "inventory-detail", "metrics-live-cards", "metrics-temperatures", "metric-list", "metric-chart",
    "config-targets", "config-users", "config-collection-facts", "config-deployment-facts"]) $(id).replaceChildren();
  show("inventory-feedback", false); show("metric-catalog-retry", false);
  show("dashboard", false); show("logout", false); show("account-menu", false); $("account-menu").open = false;
  show("auth-shell", true); show("bootstrap", false); show("initial-password", false); show("login", true);
  $("initial-password-form").reset(); show("initial-password-error", false);
  show("host-resources", false); $("host-resources").open = false;
  $("identity").textContent = ""; say(message || "Sign in required.");
  if (broadcast && hadSession) authChannel?.postMessage({type: "signed-out"});
  $("login-form").elements.namedItem("password").focus();
}

async function resumeFromCookie(session = null) {
  showLogin("Checking your session…", false);
  try {
    const current = session || await api("/api/session?observe=1");
    authEpoch++;
    csrf = current.csrf;
    if (current.password_change_required) { showInitialPassword(current); return; }
    applyRole(current); show("login", false); show("auth-shell", false);
    show("logout", true); show("dashboard", true); say("");
    if (resumePrometheus()) return;
    refreshHostResources();
    await loadServers(); route();
    await refreshOnboardingJobs();
  } catch { showLogin("Sign in to continue.", false); }
}

function resumePrometheus() {
  const parameters = new URLSearchParams(location.search);
  if (!parameters.has("prometheus_return")) return false;
  const target = safePrometheusReturn(parameters.get("prometheus_return"), location.origin);
  parameters.delete("prometheus_return");
  const remaining = parameters.toString();
  history.replaceState(null, "", location.pathname + (remaining ? "?" + remaining : "") + location.hash);
  if (!target) return false;
  location.assign(target);
  return true;
}

authChannel?.addEventListener("message", event => {
  if (event.data?.type === "signed-out" && identity) showLogin("Session ended in another tab. Sign in to continue.", false);
  if (event.data?.type === "signed-in") resumeFromCookie();
});

function route() {
  if (!identity) return;
  const hash = location.hash;
  if (hash === "#/configuration") { location.hash = "#/configuration/collection"; return; }
  const configSection = /^#\/configuration\/(collection|prometheus|console|users|application|security|backup)$/.exec(hash)?.[1] || null;
  if (hash.startsWith("#/configuration") && identity.role !== "admin") { location.hash = "#/servers"; return; }
  const isEvents = hash === "#/events";
  const isConfiguration = Boolean(configSection);
  const routeChanged = hash !== lastSidebarRoute;
  if (routeChanged) {
    setSidebarExpanded(isConfiguration ? "configuration" : "operate", true);
    lastSidebarRoute = hash;
  }
  const match = /^#\/servers\/([a-f0-9]{32})(\/(metrics|inventory))?$/.exec(hash);
  const isFleet = !isEvents && !isConfiguration && !match;
  const isMetricDetail = match?.[3] === "metrics";
  const isInventoryDetail = match?.[3] === "inventory";
  if (isInventoryDetail && inventoryServerId !== match[1]) {
    inventoryServerId = match[1];
    inventorySnapshot = null;
    inventorySignature = "";
    inventoryCategory = null;
    inventoryPage = 0;
    inventoryExpanded = new Set();
    inventorySelectedSource = null;
    $("inventory-search").value = "";
    setReadStatus($("inventory-status"), "loading", "Checking this server's inventory…", true);
    $("inventory-categories").replaceChildren();
    $("inventory-table").replaceChildren();
    $("inventory-category-title").textContent = "Inventory";
    $("inventory-count").textContent = "";
    $("inventory-page-numbers").replaceChildren();
    show("inventory-detail", false);
    show("inventory-search-label", false); show("inventory-pager", false);
  }
  currentDetail = match ? match[1] : null;
  show("fleet-page", isFleet);
  show("events-page", isEvents);
  show("configuration-page", isConfiguration);
  show("detail-page", Boolean(match));
  $("fleet-tab").classList.toggle("active", isFleet || Boolean(match));
  $("events-tab").classList.toggle("active", isEvents);
  const configLabels = {collection: "Collection", prometheus: "Prometheus", console: "Console & Session", users: "Users",
    application: "Application & Network", security: "Security", backup: "Backup & Restore"};
  if (isConfiguration) {
    $("config-title").textContent = configLabels[configSection];
    $("config-breadcrumb").textContent = `Configuration / ${configLabels[configSection]}`;
  }
  for (const section of Object.keys(configLabels)) {
    show(`config-${section}-view`, configSection === section);
    const tab = $(`config-${section}-tab`);
    tab.classList.toggle("active", configSection === section);
    if (configSection === section) tab.setAttribute("aria-current", "page"); else tab.removeAttribute("aria-current");
  }
  if (isConfiguration && routeChanged) $("config-title").focus({preventScroll: true});
  for (const [id, active] of [["fleet-tab", isFleet || Boolean(match)], ["events-tab", isEvents]]) {
    if (active) $(id).setAttribute("aria-current", "page"); else $(id).removeAttribute("aria-current");
  }
  show("detail-content", Boolean(match) && !isMetricDetail && !isInventoryDetail);
  show("detail-inventory", isInventoryDetail);
  show("detail-metrics", isMetricDetail);
  if (!isMetricDetail && $("metric-drawer").open) $("metric-drawer").close();
  if (isMetricDetail || isInventoryDetail) show("detail-source-status", false);
  $("detail-breadcrumb").textContent = `Operate / Servers / ${isMetricDetail ? "Metrics" : isInventoryDetail ? "Inventory" : "General"}`;
  $("detail-general-tab").classList.toggle("active", !isMetricDetail && !isInventoryDetail);
  $("detail-inventory-tab").classList.toggle("active", isInventoryDetail);
  $("detail-metrics-tab").classList.toggle("active", isMetricDetail);
  for (const [id, active] of [["detail-general-tab", !isMetricDetail && !isInventoryDetail], ["detail-inventory-tab", isInventoryDetail], ["detail-metrics-tab", isMetricDetail]]) {
    if (active) $(id).setAttribute("aria-current", "page"); else $(id).removeAttribute("aria-current");
  }
  if (isEvents) loadEvents().catch(error => say(error.message));
  if (match && !isMetricDetail && !isInventoryDetail) showDetail(match[1]);
  if (match && isInventoryDetail) {
    const server = servers.find(item => item.id === match[1]);
    if (server) { $("detail-name").textContent = server.name; updateDetailPowerIcon(server); $("detail-metrics-link").href = server.scrape_url; $("detail-actions").disabled = identity?.role !== "admin"; $("detail-badges").replaceChildren(badge(...health(server)), badge(...collection(server))); }
    loadInventory(match[1]);
  }
  if (match && isMetricDetail) showServerMetrics(match[1]).catch(error => say(error.message));
  if (configSection === "prometheus") prometheusView.refresh(routeChanged);
  else if (isConfiguration) loadConfiguration().catch(error => say(error.message));
}

const liveReadings = new Map();
function scheduleLiveRefreshPoll(serverId) {
  if (liveRefreshTimers.has(serverId)) return;
  const timer = setTimeout(() => {
    liveRefreshTimers.delete(serverId);
    if (document.visibilityState === "visible" && currentDetail === serverId &&
        location.hash === `#/servers/${serverId}/metrics`)
      loadServerLive(serverId).catch(error => say(error.message));
  }, 2000);
  liveRefreshTimers.set(serverId, timer);
}
function clearLiveRefreshPoll(serverId) {
  if (liveRefreshTimers.has(serverId)) clearTimeout(liveRefreshTimers.get(serverId));
  liveRefreshTimers.delete(serverId);
}
const chartColors = ["#59a9ff", "#35c9bd", "#c294fa", "#f2a56c", "#a7d46b"];
const metricLabel = series => series.labels?.name || series.labels?.sensor_id || series.labels?.metric_property || series.name;
const metricServer = series => servers.find(item => item.id === series.server_id)?.name || "Server";
const numeric = (number, unit = "") => Number.isFinite(number) ? `${Number(number).toLocaleString(undefined, {maximumFractionDigits: 2})}${unit ? ` ${unit}` : ""}` : "—";
function ageText(raw, prefix = "") {
  const seconds = Math.floor(Date.now() / 1000 - raw);
  if (!Number.isFinite(raw) || raw <= 0 || seconds < -5) return "No reading time";
  const age = Math.max(0, seconds);
  return `${prefix}${age} second${age === 1 ? "" : "s"} ago`;
}
function ageNode(raw, className = "", prefix = "") {
  const item = node("span", ageText(raw, prefix), className);
  if (Number.isFinite(raw) && raw > 0) {
    item.dataset.ageTimestamp = String(raw);
    item.dataset.agePrefix = prefix;
  }
  return item;
}
function updateAgeLabels() {
  if (document.visibilityState !== "visible" || $("dashboard").hidden) return;
  for (const item of document.querySelectorAll("[data-age-timestamp]")) {
    const raw = Number(item.dataset.ageTimestamp);
    item.textContent = ageText(raw, item.dataset.agePrefix || "");
    item.classList.toggle("old-reading", Date.now() / 1000 - raw > 300);
  }
}
function liveField(label, reading, unit = "") {
  const item = node("div", "", "live-value");
  item.append(node("span", label, "label"), node("strong", numeric(reading, unit)));
  return item;
}
async function fetchLive(server) {
  try {
    const result = await api(`/api/servers/${encodeURIComponent(server.id)}/live-metrics`, "GET", null, 60000);
    liveReadings.set(server.id, result);
    return {data: result, failed: false};
  } catch {
    return {data: liveReadings.get(server.id) || null, failed: true};
  }
}
function renderTemperatureGrid(data) {
  const list = $("metrics-temperatures"); list.replaceChildren();
  if (!Number.isFinite(data?.temperatures?.fetched_at)) {
    list.append(node("p", "No temperature readings are available yet.", "muted")); return;
  }
  const query = $("temperature-search").value.trim().toLowerCase();
  const items = (data?.temperatures?.items || []).filter(item =>
    `${item.name} ${item.id}`.toLowerCase().includes(query));
  if (!items.length) { list.append(node("p", "No temperature readings match this view.", "muted")); return; }
  for (const item of items) {
    const cell = node("div", "", "temperature-item");
    cell.append(node("span", item.name), node("strong", numeric(item.celsius, "°C")));
    cell.title = item.id; list.append(cell);
  }
}
async function loadServerLive(serverId) {
  const server = servers.find(item => item.id === serverId);
  if (!server) return;
  if (livePending.has(serverId)) return;
  const request = ++liveRequest;
  const isActive = () => identity && request === liveRequest && currentDetail === serverId &&
    location.hash === `#/servers/${serverId}/metrics`;
  const status = $("metrics-live-status");
  if (!server.manager_metrics_enabled) {
    clearLiveRefreshPoll(serverId);
    liveReadings.delete(serverId);
    liveRenderedServerId = null;
    if (isActive()) {
      $("metrics-live-section").setAttribute("aria-busy", "false");
      setReadStatus(status, "cached", "Manager metric collection is off. Values below are not being refreshed.");
      $("metrics-live-cards").replaceChildren(node("p", "Live readings are paused. External Prometheus can still scrape this server's exporter.", "empty-state"));
      $("metrics-temperatures").replaceChildren(node("p", "Temperature reads are paused.", "muted"));
    }
    return;
  }
  $("metrics-live-section").setAttribute("aria-busy", "true");
  if (!liveReadings.has(serverId)) {
    setReadStatus(status, "loading", "Checking Redfish readings…", true);
    $("metrics-live-cards").replaceChildren(node("p", "Checking power and host state…", "read-placeholder"));
    $("metrics-temperatures").replaceChildren(node("p", "Checking temperatures…", "read-placeholder"));
  }
  const checking = setTimeout(() => {
    if (isActive()) setReadStatus(status, "loading", "Checking Redfish readings… last-known values remain visible.", true);
  }, 400);
  livePending.add(serverId);
  let result;
  try { result = await fetchLive(server); }
  finally { livePending.delete(serverId); }
  const {data, failed: networkFailed} = result;
  const failed = networkFailed || Boolean(data?.refresh_error);
  const refreshing = !networkFailed && Boolean(data?.refreshing || data?.queued);
  clearTimeout(checking);
  if (!isActive()) return;
  $("metrics-live-section").setAttribute("aria-busy", "false");
  if (!server.manager_metrics_enabled) return loadServerLive(serverId);
  if (data?.collection_enabled === false) {
    server.manager_metrics_enabled = false;
    $("metrics-collection-note").textContent = "Disabled";
    show("metrics-disabled-banner", true);
    $("metric-last-heading").textContent = "Last-known value";
    return loadServerLive(serverId);
  }
  if (refreshing) scheduleLiveRefreshPoll(serverId);
  else clearLiveRefreshPoll(serverId);
  if (refreshing && !data?.power && !data?.system && !data?.temperatures) {
    setReadStatus(status, "loading", "Checking Redfish readings…", true);
    $("metrics-live-cards").replaceChildren(node("p", "Checking power and host state…", "read-placeholder"));
    $("metrics-temperatures").replaceChildren(node("p", "Checking temperatures…", "read-placeholder"));
    return;
  }
  if (!data) {
    setReadStatus(status, "error", "Readings unavailable. The latest check failed; retry when the BMC responds.");
    $("metrics-live-cards").replaceChildren(node("p", "No power or host-state reading is available yet.", "empty-state"));
    $("metrics-temperatures").replaceChildren(node("p", "No temperature reading is available yet.", "muted"));
    return;
  }
  const thermalAge = Date.now() / 1000 - data?.temperatures?.fetched_at;
  const now = Date.now() / 1000;
  const sectionTimes = [data?.power?.fetched_at, data?.system?.fetched_at, data?.temperatures?.fetched_at];
  const newestRead = Math.max(...sectionTimes.filter(Number.isFinite), 0);
  const lastKnown = failed || !newestRead || sectionTimes.every(time => !Number.isFinite(time) || now - time > 300);
  const partial = Boolean(data?.errors?.length) || !Number.isFinite(data?.power?.fetched_at) ||
    !Number.isFinite(data?.system?.fetched_at) || !Number.isFinite(data?.temperatures?.fetched_at) ||
    sectionTimes.some(time => Number.isFinite(time) && now - time > 300);
  setReadStatus(status, refreshing ? "loading" : failed ? "error" : lastKnown ? "cached" : partial ? "partial" : "current",
    `${refreshing ? "Refreshing Redfish · last-known readings remain visible" : failed ? "Latest check failed · last-known readings" : lastKnown ? "Last-known readings" : partial ? "Partially updated readings" : "Current readings"} · thermal ${Number.isFinite(thermalAge) ? `last read ${formatTime(data.temperatures.fetched_at * 1000)}` : "unavailable"}`,
    refreshing);
  const signature = JSON.stringify([data.power, data.system, data.temperatures, data.errors, failed, refreshing,
    Date.now() / 1000 - data?.power?.fetched_at > 300,
    Date.now() / 1000 - data?.system?.fetched_at > 300,
    Date.now() / 1000 - data?.temperatures?.fetched_at > 300]);
  if (liveRenderedServerId === serverId && liveSignatures.get(serverId) === signature) {
    updateAgeLabels(); return;
  }
  liveSignatures.set(serverId, signature);
  liveRenderedServerId = serverId;
  const cards = $("metrics-live-cards"); cards.replaceChildren();
  const usingCached = failed || refreshing;
  const power = data?.power || {};
  const main = node("div", "", "live-server"); main.append(node("h3", "Chassis power"));
  const current = Number.isFinite(power.current_watts);
  const powerAvailable = Number.isFinite(power.fetched_at);
  const values = node("div", "", "live-values");
  values.append(liveField(current ? "Current" : "Average", powerAvailable ? (current ? power.current_watts : power.average_watts) : null, "W"),
                liveField("Minimum", powerAvailable ? power.minimum_watts : null, "W"), liveField("Maximum", powerAvailable ? power.maximum_watts : null, "W"));
  main.append(values);
  if (!current) main.append(node("span", "BMC-reported average/min/max; reporting window not advertised.", "live-note"));
  main.append(ageNode(power.fetched_at, "live-age", usingCached ? "Last confirmed " : "Read "));
  main.append(node("span", usingCached || !powerAvailable || Date.now() / 1000 - power.fetched_at > 300 ? "Last known" : "Current", "read-marker " +
    (usingCached || !powerAvailable || Date.now() / 1000 - power.fetched_at > 300 ? "cached" : "current"))); cards.append(main);
  const state = node("div", "", "live-server"); state.append(node("h3", "Host state"));
  state.append(node("strong", Number.isFinite(data?.system?.fetched_at) ? (data?.system?.power_state || "Unavailable") : "Unavailable"));
  state.append(ageNode(data?.system?.fetched_at, "live-age", usingCached ? "Last confirmed " : "Read "));
  state.append(node("span", usingCached || !Number.isFinite(data?.system?.fetched_at) || Date.now() / 1000 - data.system.fetched_at > 300 ? "Last known" : "Current", "read-marker " +
    (usingCached || !Number.isFinite(data?.system?.fetched_at) || Date.now() / 1000 - data.system.fetched_at > 300 ? "cached" : "current"))); cards.append(state);
  renderTemperatureGrid(data);
  updateAgeLabels();
}

function svgNode(tag, attributes = {}) {
  const item = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [name, raw] of Object.entries(attributes)) item.setAttribute(name, String(raw));
  return item;
}
function chartPeriods(history, first, until) {
  const disabled = (history.disabled_intervals || []).map(item => ({
    start: Math.max(first, item.start), end: Math.min(until, item.end), kind: "disabled"
  })).filter(item => item.end > item.start);
  const points = (history.points || []).filter(item => item.sampled_at >= first && item.sampled_at <= until)
    .sort((a, b) => a.sampled_at - b.sampled_at);
  const threshold = Math.max(600, 3 * (Number(history.expected_interval_seconds) || 300));
  const missing = [];
  if (!points.length) missing.push({start: first, end: until, kind: "missing"});
  else if (points[0].sampled_at - first > threshold)
    missing.push({start: first, end: points[0].sampled_at, kind: "missing"});
  for (let i = 1; i < points.length; i++) {
    if (points[i].sampled_at - points[i - 1].sampled_at > threshold)
      missing.push({start: points[i - 1].sampled_at + threshold, end: points[i].sampled_at, kind: "missing"});
  }
  if (points.length && until - points[points.length - 1].sampled_at > threshold)
    missing.push({start: points[points.length - 1].sampled_at + threshold, end: until, kind: "missing"});
  // Orange policy pauses take precedence over unexplained no-sample gaps.
  const neutral = missing.flatMap(gap => {
    let pieces = [gap];
    for (const pause of disabled) pieces = pieces.flatMap(piece => {
      if (pause.end <= piece.start || pause.start >= piece.end) return [piece];
      return [{start: piece.start, end: Math.min(piece.end, pause.start), kind: "missing"},
              {start: Math.max(piece.start, pause.end), end: piece.end, kind: "missing"}]
        .filter(part => part.end > part.start);
    });
    return pieces;
  });
  return {disabled, neutral, threshold};
}
function chartLineSegments(points, periods) {
  if (!points.length) return [];
  const bands = [...periods.neutral, ...periods.disabled].sort((a, b) => a.start - b.start);
  const segments = [];
  let current = [points[0]];
  for (let index = 1; index < points.length; index++) {
    const previous = points[index - 1], next = points[index];
    if (next.sampled_at <= previous.sampled_at) continue;
    const interpolated = stamp => ({sampled_at: stamp, value: previous.value +
      (next.value - previous.value) * (stamp - previous.sampled_at) / (next.sampled_at - previous.sampled_at)});
    for (const band of bands) {
      const start = Math.max(previous.sampled_at, band.start);
      const end = Math.min(next.sampled_at, band.end);
      if (end <= start) continue;
      if (current[current.length - 1].sampled_at < start) current.push(interpolated(start));
      segments.push(current);
      current = [interpolated(end)];
    }
    if (current[current.length - 1].sampled_at < next.sampled_at) current.push(next);
  }
  segments.push(current);
  return segments;
}
function renderChart(container, histories, hours) {
  container.replaceChildren();
  const series = histories.filter(Boolean);
  if (!series.length) { container.append(node("p", "No metric history is available.", "empty-state")); return; }
  const until = series[0].range_end || Date.now() / 1000;
  const first = until - hours * 3600;
  const all = series.flatMap(item => item.points).filter(point => point.sampled_at >= first && point.sampled_at <= until);
  let low = all.length ? Math.min(...all.map(point => point.value)) : 0;
  let high = all.length ? Math.max(...all.map(point => point.value)) : 1;
  if (high === low) { low -= 1; high += 1; }
  const svg = svgNode("svg", {viewBox: "0 0 780 260", role: "img", "aria-label": "Historical metric line chart", class: "chart-svg"});
  const left = 58, right = 755, top = 18, bottom = 220;
  const defs = svgNode("defs");
  const hatch = svgNode("pattern", {id: "missing-samples-hatch", width: 8, height: 8, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)"});
  hatch.append(svgNode("rect", {width: 8, height: 8, fill: "#e8edf2"}),
               svgNode("line", {x1: 0, y1: 0, x2: 0, y2: 8, stroke: "#c3ccd5", "stroke-width": 2}));
  defs.append(hatch); svg.append(defs);
  const periods = chartPeriods(series[0], first, until);
  for (const item of [...periods.neutral, ...periods.disabled]) {
    const x = left + (right - left) * (item.start - first) / (hours * 3600);
    const width = (right - left) * (item.end - item.start) / (hours * 3600);
    const band = svgNode("rect", {x, y: top, width, height: bottom - top,
      fill: item.kind === "disabled" ? "#f5c98e" : "url(#missing-samples-hatch)", opacity: item.kind === "disabled" ? 0.5 : 0.7});
    const title = svgNode("title"); title.textContent = item.kind === "disabled" ? "Manager metrics disabled" : "No manager samples; cause not confirmed";
    band.append(title); svg.append(band);
  }
  for (let step = 0; step <= 4; step++) {
    const y = top + (bottom - top) * step / 4;
    svg.append(svgNode("line", {x1: left, y1: y, x2: right, y2: y, stroke: "#dce6ef"}));
    const tick = svgNode("text", {x: 50, y: y + 4, "text-anchor": "end", fill: "#72889a", "font-size": 11});
    tick.textContent = numeric(high - (high - low) * step / 4); svg.append(tick);
  }
  for (let step = 0; step <= 4; step++) {
    const x = left + (right - left) * step / 4;
    const tick = svgNode("text", {x, y: 245, "text-anchor": "middle", fill: "#72889a", "font-size": 11});
    tick.textContent = new Date((first + hours * 3600 * step / 4) * 1000).toLocaleString(undefined,
      hours >= 168 ? {month: "short", day: "numeric"} : {hour: "2-digit", minute: "2-digit"});
    svg.append(tick);
  }
  const legend = node("div", "", "chart-legend");
  series.forEach((item, index) => {
    const color = chartColors[index % chartColors.length];
    const points = item.points.filter(point => point.sampled_at >= first && point.sampled_at <= until);
    const coordinates = point => `${(left + (right - left) * (point.sampled_at - first) / (hours * 3600)).toFixed(2)},${(bottom - (bottom - top) * (point.value - low) / (high - low)).toFixed(2)}`;
    const drawSegment = segment => {
      if (segment.length > 1) svg.append(svgNode("polyline", {points: segment.map(coordinates).join(" "), fill: "none", stroke: color, "stroke-width": 2.5, "stroke-linejoin": "round"}));
      else if (segment.length === 1) {
        const [cx, cy] = coordinates(segment[0]).split(","); svg.append(svgNode("circle", {cx, cy, r: 4, fill: color}));
      }
    };
    for (const segment of chartLineSegments(points, periods)) drawSegment(segment);
    const label = node("span", "", "legend-item");
    const swatch = node("span", "", "legend-color"); swatch.style.backgroundColor = color;
    label.append(swatch, node("span", `${metricServer(item.series)} · ${metricLabel(item.series)}`)); legend.append(label);
  });
  container.append(svg, legend);
  if (!all.length) container.append(node("p", "No samples in this time range.", "chart-help"));
  const annotations = node("div", "", "chart-period-legend");
  if (periods.disabled.length) annotations.append(node("span", "Manager metrics disabled in the orange period", "chart-period-disabled"));
  if (periods.neutral.length) annotations.append(node("span", "No manager samples in the gray period; cause not confirmed", "chart-period-missing"));
  if (annotations.childElementCount) container.append(annotations);
  if (series.length === 1 && series[0].statistics) {
    const stats = series[0].statistics; const unit = series[0].series.unit;
    const row = node("div", "", "chart-stats");
    for (const [label, reading] of [["Last", stats.last], ["Average", stats.average], ["Minimum", stats.minimum], ["Maximum", stats.maximum]])
      row.append(node("span", `${label}: ${numeric(reading, unit)}`));
    container.append(row);
  }
}

async function showMetricHistory(series) {
  const previousId = currentMetric?.id;
  currentMetric = series;
  ++chartRequest;
  chartSignature = "";
  $("metric-chart-title").textContent = `${series.name} · ${metricLabel(series)}`;
  const body = $("metric-chart"); body.replaceChildren(node("p", "Loading history…", "chart-help"));
  const drawer = $("metric-drawer");
  if (!drawer.open) drawer.showModal();
  try {
    if (previousId !== series.id && identity?.role === "admin") await api(`/api/metrics/series/${encodeURIComponent(series.id)}/track`, "POST");
    await refreshOpenMetricHistory();
  } catch (error) {
    if (drawer.open && currentMetric?.id === series.id) body.replaceChildren(node("p", `History unavailable: ${error.message}`, "empty-state"));
  }
}
async function refreshOpenMetricHistory() {
  const series = currentMetric;
  const drawer = $("metric-drawer");
  const requestId = chartRequest;
  if (!drawer.open || !series || chartRefreshPending === requestId) return;
  chartRefreshPending = requestId;
  const hours = Number($("metric-range").value);
  try {
    const history = await api(`/api/metrics/series/${encodeURIComponent(series.id)}/history?hours=${hours}`);
    if (!drawer.open || requestId !== chartRequest) return;
    const signature = JSON.stringify([series.id, hours, history.points, history.statistics,
      history.disabled_intervals, history.range_end]);
    if (signature !== chartSignature) {
      chartSignature = signature;
      renderChart($("metric-chart"), [history], hours);
    }
  } finally {
    if (chartRefreshPending === requestId) chartRefreshPending = 0;
  }
}
async function loadMetricCatalog(serverId) {
  const requestId = ++catalogRequest;
  const search = $("metric-search").value.trim();
  const active = () => identity && requestId === catalogRequest && currentDetail === serverId &&
    location.hash === `#/servers/${serverId}/metrics`;
  $("metric-catalog-section").setAttribute("aria-busy", "true");
  if (!$("metric-list").childElementCount) setReadStatus($("metric-catalog-status"), "loading", "Checking saved metric series…", true);
  const checking = setTimeout(() => {
    if (active()) setReadStatus($("metric-catalog-status"), "loading", "Checking saved metric series… last-known rows remain visible.", true);
  }, 400);
  let catalog;
  try {
    catalog = await api(`/api/metrics/series?server_id=${encodeURIComponent(serverId)}&search=${encodeURIComponent(search)}&limit=100`, "GET", null, 15000);
  } catch {
    clearTimeout(checking);
    if (!active()) return;
    $("metric-catalog-section").setAttribute("aria-busy", "false");
    setReadStatus($("metric-catalog-status"), "error", $("metric-list").childElementCount ?
      "Could not check saved metrics · showing last-known rows." : "Saved metrics are unavailable. Retry this view.");
    show("metric-catalog-retry", true);
    return;
  }
  clearTimeout(checking);
  if (!active()) return;
  $("metric-catalog-section").setAttribute("aria-busy", "false");
  $("metric-catalog-status").textContent = "";
  $("metric-catalog-status").hidden = true;
  show("metric-catalog-retry", false);
  if ($("workspace-notice-text").textContent === "Failed to fetch") say("");
  const signature = JSON.stringify([serverId, search, catalog.map(series =>
    [series.id, series.value, series.updated_at])]);
  if (signature === catalogSignature) return;
  catalogSignature = signature;
  $("metric-count").textContent = `${catalog.length}${catalog.length === 100 ? "+" : ""} matching series`;
  const list = $("metric-list"); list.replaceChildren(); show("metric-empty", !catalog.length);
  for (const series of catalog) {
    const row = node("tr");
    const name = node("td", series.name, "mono"); name.title = series.name;
    const lastValue = node("td", "", "metric-last");
    lastValue.append(node("strong", numeric(series.value, series.unit)), ageNode(series.updated_at, "metric-age", "Value time "));
    row.append(name, node("td", metricLabel(series)), lastValue,
               node("td", formatTime(series.updated_at * 1000)));
    const action = node("td"); const view = node("button", "View chart"); view.type = "button";
    view.setAttribute("aria-label", `View chart for ${metricLabel(series)}`);
    view.addEventListener("click", () => showMetricHistory(series)); action.append(view); row.append(action); list.append(row);
  }
  updateAgeLabels();
}
async function showServerMetrics(serverId) {
  const server = servers.find(item => item.id === serverId);
  if (!server) { location.hash = "#/servers"; say("Server not found."); return; }
  $("detail-name").textContent = server.name;
  updateDetailPowerIcon(server);
  $("detail-metrics-link").href = server.scrape_url;
  $("detail-actions").disabled = identity?.role !== "admin";
  $("detail-badges").replaceChildren(badge(...health(server)), badge(...collection(server)));
  $("metrics-collection-note").textContent = server.manager_metrics_enabled
    ? "Enabled · live values and 24-hour charts"
    : "Disabled";
  show("metrics-disabled-banner", !server.manager_metrics_enabled);
  $("metric-last-heading").textContent = server.manager_metrics_enabled ? "Last value" : "Last-known value";
  if (metricsServerId !== serverId) {
    metricsServerId = serverId;
    liveRenderedServerId = null;
    catalogSignature = "";
    $("metric-list").replaceChildren();
    $("metrics-live-cards").replaceChildren();
    $("metrics-temperatures").replaceChildren();
    $("metric-count").textContent = "";
    $("metric-catalog-status").textContent = "";
    show("metric-catalog-retry", false);
  }
  currentMetric = null;
  await Promise.all([loadServerLive(serverId), loadMetricCatalog(serverId)]);
}

async function initialize() {
  let session;
  try {
    const setup = await api("/api/bootstrap-required");
    if (setup.required) { show("bootstrap", true); return; }
    session = await api("/api/session");
  } catch { show("login", true); return; }
  authEpoch++;
  csrf = session.csrf;
  if (session.password_change_required) { showInitialPassword(session); return; }
  applyRole(session); show("logout", true); show("auth-shell", false); show("dashboard", true);
  refreshHostResources();
  try { await loadServers(); route(); await refreshOnboardingJobs(); } catch (error) { say(`Fleet data unavailable: ${error.message}`); }
}

$("bootstrap-form").addEventListener("submit", async event => {
  event.preventDefault(); const form = new FormData(event.target);
  try { await api("/api/bootstrap", "POST", {token: form.get("token"), password: form.get("password")}); event.target.reset(); show("bootstrap", false); show("login", true); say("Admin account created. Sign in."); }
  catch (error) { say(error.message); }
});
$("login-form").addEventListener("submit", async event => {
  event.preventDefault(); const form = new FormData(event.target);
  try {
    const result = await api("/api/login", "POST", {username: form.get("username"), password: form.get("password")});
    authEpoch++; csrf = result.csrf; event.target.reset();
    if (result.password_change_required) {
      showInitialPassword(result);
      authChannel?.postMessage({type: "signed-in"});
      return;
    }
    show("login", false); show("auth-shell", false); show("dashboard", true);
    show("logout", true); applyRole(result); say("");
    authChannel?.postMessage({type: "signed-in"});
    if (resumePrometheus()) return;
    await loadServers(); route(); await refreshOnboardingJobs();
    refreshHostResources();
  } catch (error) { say(error.message); }
});
$("initial-password-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.target;
  const password = form.elements.namedItem("password").value;
  const confirmation = form.elements.namedItem("confirmation").value;
  const error = $("initial-password-error");
  if (password !== confirmation) {
    error.textContent = "Passwords do not match.";
    show("initial-password-error", true);
    error.focus();
    return;
  }
  show("initial-password-error", false);
  try {
    await api("/api/initial-password", "PUT", {password});
    showLogin("Password changed. Sign in with your new password.");
  } catch (failure) {
    error.textContent = failure.message;
    show("initial-password-error", true);
    error.focus();
  }
});
$("initial-signout").addEventListener("click", async () => {
  try { await api("/api/logout", "POST"); showLogin("Signed out."); }
  catch (error) { say(error.message); }
});
$("logout").addEventListener("click", async () => {
  try { await api("/api/logout", "POST"); showLogin("Signed out."); }
  catch (error) { say(error.message); }
});
$("fleet-tab").addEventListener("click", () => { location.hash = "#/servers"; });
$("events-tab").addEventListener("click", () => { location.hash = "#/events"; });
for (const group of ["operate", "configuration"]) {
  $(`${group}-heading`).addEventListener("click", () => {
    const heading = $(`${group}-heading`);
    setSidebarExpanded(group, heading.getAttribute("aria-expanded") !== "true");
  });
}
for (const section of ["collection", "prometheus", "console", "users", "application", "security", "backup"]) {
  $(`config-${section}-tab`).addEventListener("click", () => { location.hash = `#/configuration/${section}`; });
}
$("back-to-fleet").addEventListener("click", () => { location.hash = "#/servers"; });
$("detail-general-tab").addEventListener("click", () => { if (currentDetail) location.hash = `#/servers/${currentDetail}`; });
$("detail-inventory-tab").addEventListener("click", () => { if (currentDetail) location.hash = `#/servers/${currentDetail}/inventory`; });
$("detail-metrics-tab").addEventListener("click", () => { if (currentDetail) location.hash = `#/servers/${currentDetail}/metrics`; });
$("detail-actions").addEventListener("click", () => {
  const server = servers.find(item => item.id === currentDetail);
  if (server) openActionsMenu(server, $("detail-actions"));
});
$("inventory-refresh").addEventListener("click", async () => {
  if (!currentDetail) return;
  try { await api(`/api/servers/${currentDetail}/inventory/refresh`, "POST"); say("Inventory refresh started."); await loadInventory(currentDetail); }
  catch (error) { say(error.message); }
});
$("inventory-retry").addEventListener("click", () => { if (currentDetail) loadInventory(currentDetail); });
$("inventory-back").addEventListener("click", () => { inventorySelectedSource = null; renderInventory(); });
$("inventory-search").addEventListener("input", () => { inventoryPage = 0; show("inventory-detail", false); renderInventory(); });
$("inventory-prev").addEventListener("click", () => { inventoryPage = Math.max(0, inventoryPage - 1); show("inventory-detail", false); renderInventory(); });
$("inventory-next").addEventListener("click", () => { inventoryPage++; show("inventory-detail", false); renderInventory(); });
$("collection-settings-form").addEventListener("submit", async event => {
  event.preventDefault(); const form = event.target;
  const values = Object.fromEntries([...new FormData(form)].map(([key, raw]) => [key, Number(raw)]));
  try { await api("/api/configuration/collection", "PATCH", values); say("Collection settings saved and effective immediately."); }
  catch (error) { say(error.message); }
});
$("console-settings-form").addEventListener("submit", async event => {
  event.preventDefault();
  const minutes = Number(event.target.elements.namedItem("idle_minutes").value);
  const loginMinutes = Number($("login-settings-form").elements.namedItem("login_idle_minutes").value);
  try { await api("/api/configuration/console", "PATCH", {idle_minutes: minutes, login_idle_minutes: loginMinutes}); say("Console and sign-in timeouts saved and effective immediately."); }
  catch (error) { say(error.message); }
});
$("login-settings-form").addEventListener("submit", async event => {
  event.preventDefault();
  const idle = Number($("console-settings-form").elements.namedItem("idle_minutes").value);
  const login = Number(event.target.elements.namedItem("login_idle_minutes").value);
  try { await api("/api/configuration/console", "PATCH", {idle_minutes: idle, login_idle_minutes: login}); say("Sign-in timeout saved and effective for open sessions."); }
  catch (error) { say(error.message); }
});
$("deployment-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.target;
  const values = Object.fromEntries([...new FormData(form)].filter(([key]) => key !== "acknowledge_interruption"));
  for (const key of ["manager_port", "port_start", "port_end", "console_port_offset"]) values[key] = Number(values[key]);
  values.acknowledge_interruption = form.elements.namedItem("acknowledge_interruption").checked;
  configError("deployment-error");
  try {
    const previousAt = deploymentLastAt;
    await api("/api/configuration/deployment", "PUT", values);
    const advertised = values.advertised_dns_name.trim() || values.bind_address;
    const host = advertised.includes(":") ? `[${advertised}]` : advertised;
    const reconnectUrl = `https://${host}:${values.manager_port}/#/configuration/application`;
    watchDeployment("deployment-result", previousAt, reconnectUrl);
  } catch (error) { configError("deployment-error", error.message); }
});
for (const eventName of ["input", "change"]) $("deployment-form").addEventListener(eventName, renderDeploymentImpact);
$("certificate-form").addEventListener("submit", async event => {
  event.preventDefault(); const form = event.target;
  const values = Object.fromEntries(new FormData(form));
  values.acknowledge_interruption = form.elements.namedItem("acknowledge_interruption").checked;
  configError("certificate-error");
  try {
    const previousAt = deploymentLastAt;
    await api("/api/configuration/certificate", "PUT", values);
    form.reset(); // Clear the private key as soon as the manager accepts it.
    watchDeployment("certificate-result", previousAt);
  } catch (error) { configError("certificate-error", error.message); }
});
$("certificate-generate").addEventListener("click", async () => {
  if (!confirm("Replace the current certificate with a new 10-year self-signed certificate? HTTPS will restart, and browsers and Prometheus must trust the new certificate.")) return;
  const additional_hosts = $("certificate-extra-hosts").value.split(",").map(value => value.trim()).filter(Boolean);
  configError("certificate-generate-error");
  try {
    const previousAt = deploymentLastAt;
    await api("/api/configuration/certificate/generate", "POST", {additional_hosts});
    watchDeployment("certificate-result", previousAt);
  } catch (error) { configError("certificate-generate-error", error.message); }
});
$("bmc-ca-form").addEventListener("submit", async event => {
  event.preventDefault(); const form = event.target;
  configError("bmc-ca-error");
  const caPem = form.elements.namedItem("ca_pem").value.trim();
  if (!caPem) {
    configError("bmc-ca-error", "Paste a PEM CA bundle, or use Restore system trust.");
    return;
  }
  try {
    const previousAt = deploymentLastAt;
    await api("/api/configuration/bmc-ca", "PUT", {ca_pem: caPem});
    watchDeployment("bmc-ca-result", previousAt, "", () => form.reset());
  } catch (error) { configError("bmc-ca-error", error.message); }
});
$("bmc-ca-clear").addEventListener("click", async () => {
  if (!confirm("Remove the custom BMC CA? Connections relying on it may fail. Exporters will restart.")) return;
  configError("bmc-ca-error");
  try {
    const previousAt = deploymentLastAt;
    await api("/api/configuration/bmc-ca", "PUT", {ca_pem: "", confirm_clear: true});
    watchDeployment("bmc-ca-result", previousAt, "", () => $("bmc-ca-form").reset());
  } catch (error) { configError("bmc-ca-error", error.message); }
});
$("backup-cancel").addEventListener("click", () => backupAbortController?.abort());
function backupProgressText(state) {
  const phase = {checking: "Checking space", "checking-space": "Checking space",
    "preparing-history": "Preparing history", encrypting: "Encrypting archive",
    verifying: "Verifying archive"}[state.phase] || "Preparing backup";
  return state.total > 0 ? `${phase}… ${state.current.toLocaleString()} / ${state.total.toLocaleString()} bytes` : `${phase}…`;
}
function renderReadyBackup(state) {
  const result = $("backup-result"); result.replaceChildren();
  result.append(node("span", `Ready to download · ${state.bytes.toLocaleString()} bytes `));
  const link = node("a", "Download backup");
  link.href = `/api/backup/jobs/${encodeURIComponent(state.id)}/download`;
  link.download = state.filename;
  link.addEventListener("click", () => {
    result.replaceChildren(node("span", "Download started; check that your browser saved the file. Keep the passphrase separately."));
  });
  const discard = node("button", "Discard backup", "button outline"); discard.type = "button";
  discard.addEventListener("click", async () => {
    discard.disabled = true;
    try {
      await api(`/api/backup/jobs/${encodeURIComponent(state.id)}`, "DELETE");
      result.textContent = "Prepared backup discarded.";
    } catch (error) { discard.disabled = false; configError("backup-error", error.message); }
  });
  const details = node("details");
  details.append(node("summary", "Archive details"), node("p", state.filename),
    node("p", `SHA-256 ${state.sha256}`), node("p", "Available for this session for up to 15 minutes."));
  result.append(link, node("span", " "), discard, details);
}
async function watchBackupPreparation(operation, controller, requestEpoch) {
  let cancellationSent = false;
  while (requestEpoch === authEpoch && identity) {
      if (controller.signal.aborted && !cancellationSent) {
        await api(`/api/backup/jobs/${encodeURIComponent(operation)}`, "DELETE");
        cancellationSent = true;
        $("backup-result").textContent = "Canceling preparation…";
      }
      const state = await api(`/api/backup/jobs/${encodeURIComponent(operation)}`, "GET", null, 10000);
      if (requestEpoch !== authEpoch || !identity) return;
      if (state.status === "ready") { renderReadyBackup(state); break; }
      if (["cancelled", "expired"].includes(state.status)) {
        $("backup-result").textContent = state.status === "cancelled" ?
          "Preparation canceled; temporary backup files removed." : "Prepared backup expired. Prepare it again.";
        break;
      }
      if (state.status === "failed") {
        $("backup-result").textContent = "Preparation failed; temporary backup files removed.";
        configError("backup-error", state.detail || "Backup preparation failed");
        break;
      }
      if (!cancellationSent) $("backup-result").textContent = backupProgressText(state);
      await new Promise(resolve => setTimeout(resolve, 500));
    }
}
async function resumeBackupPreparation() {
  if (backupAbortController || identity?.role !== "admin" || location.hash !== "#/configuration/backup") return;
  const requestEpoch = authEpoch;
  const form = $("backup-form");
  const buttons = [...form.querySelectorAll("button[type=submit]")];
  buttons.forEach(button => { button.disabled = true; });
  let state;
  try { state = await api("/api/backup/job", "GET", null, 4000); }
  catch (error) {
    if (requestEpoch === authEpoch && identity) {
      $("backup-result").textContent = "Backup status is unknown. Reload this page to check it before preparing another.";
      configError("backup-error", error.message);
    }
    return;
  }
  if (requestEpoch !== authEpoch || !identity || backupAbortController) return;
  buttons.forEach(button => { button.disabled = false; });
  if (!state) return;
  if (state.status === "ready") { renderReadyBackup(state); return; }
  if (state.status !== "preparing") return;
  const controller = new AbortController();
  backupAbortController = controller;
  buttons.forEach(button => { button.disabled = true; });
  form.setAttribute("aria-busy", "true");
  $("backup-cancel").hidden = false;
  let statusKnown = true;
  try { await watchBackupPreparation(state.id, controller, requestEpoch); }
  catch (error) {
    statusKnown = false;
    if (requestEpoch === authEpoch && identity) {
      $("backup-result").textContent = "Backup status is unknown. Reload this page to check it before preparing another.";
      configError("backup-error", error.message);
    }
  }
  finally {
    if (backupAbortController === controller) backupAbortController = null;
    if (requestEpoch === authEpoch && identity) {
      form.removeAttribute("aria-busy");
      $("backup-cancel").hidden = true;
      buttons.forEach(button => { button.disabled = !statusKnown; });
    }
  }
}
$("backup-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.target;
  const scope = event.submitter?.value;
  let passphrase = form.elements.namedItem("passphrase").value;
  let confirmation = form.elements.namedItem("passphrase_confirm").value;
  configError("backup-error");
  if (passphrase !== confirmation) { configError("backup-error", "Passphrases do not match."); return; }
  if (!["full", "servers"].includes(scope)) return;
  const buttons = [...form.querySelectorAll("button[type=submit]")];
  buttons.forEach(button => { button.disabled = true; });
  const controller = new AbortController();
  backupAbortController = controller;
  form.setAttribute("aria-busy", "true");
  $("backup-result").textContent = "Checking space…";
  const requestEpoch = authEpoch;
  let operation = null;
  let statusKnown = true;
  try {
    let accepted;
    try {
      accepted = await api("/api/backup/jobs", "POST", {scope, passphrase,
        acknowledge_sensitive: form.elements.namedItem("acknowledge_sensitive").checked});
    } catch (error) {
      if (requestEpoch !== authEpoch || !identity) throw error;
      // A lost acknowledgement can still leave a running job. Never replay POST.
      let owned;
      try { owned = await api("/api/backup/job", "GET", null, 10000); }
      catch (lookupError) { statusKnown = false; throw lookupError; }
      if (!owned || !["ready", "preparing"].includes(owned.status)) throw error;
      accepted = owned;
    }
    if (requestEpoch !== authEpoch || !identity) return;
    operation = accepted.id;
    passphrase = ""; confirmation = "";
    form.elements.namedItem("passphrase").value = "";
    form.elements.namedItem("passphrase_confirm").value = "";
    $("backup-cancel").hidden = false;
    await watchBackupPreparation(operation, controller, requestEpoch);
  } catch (error) {
    if (requestEpoch === authEpoch && identity) {
      if (operation) statusKnown = false;
      $("backup-result").textContent = !statusKnown ? "Backup status is unknown. Reload this page to check it before preparing another." : "";
      configError("backup-error", error.message || "Backup failed. Check the manager connection.");
    }
  } finally {
    if (backupAbortController === controller) backupAbortController = null;
    if (requestEpoch === authEpoch && identity) {
      form.removeAttribute("aria-busy");
      $("backup-cancel").hidden = true;
      form.elements.namedItem("passphrase").value = "";
      form.elements.namedItem("passphrase_confirm").value = "";
      buttons.forEach(button => { button.disabled = !statusKnown; });
    }
  }
});
function renderRestorePreview(manifest, plan, digest, replacementSelected) {
  const target = $("restore-preview-result"); target.replaceChildren();
  const heading = node("h4", `${manifest.scope === "full" ? "Full installation" : "Servers only"} · ${plan.server_count} claimed server${plan.server_count === 1 ? "" : "s"}`);
  heading.tabIndex = -1;
  const facts = node("div", "", "config-facts");
  const fact = (label, value) => {
    const item = node("div", "", "config-fact");
    item.append(node("strong", label), node("span", value));
    facts.append(item);
  };
  const details = node("details");
  details.append(node("summary", "Archive details"),
    node("p", `Format ${manifest.archive_format || manifest.format}`),
    node("p", `Application version ${manifest.application_version || "not recorded"}`),
    node("p", `Source installation ${manifest.source_installation_id || "not recorded"}`),
    node("p", `SHA-256 ${digest}`));
  target.append(heading,
    node("p", `Source ${manifest.source_manager_origin || "not recorded"} · ${new Date(manifest.created_at).toLocaleString()}`, "muted"),
    facts);
  if (manifest.scope === "full") {
    fact("Replaces", `Current installation: ${plan.destination_server_count} servers, users, settings, history, network, certificates, and tokens. Sessions end.`);
    fact("Resulting manager", plan.result_url);
    fact("Rollback manager", plan.current_url || "Unavailable");
    fact("Archived admin account", `${plan.source_admin_users?.join(", ") || "None found"} · existing password required`);
    fact("Manager", `${plan.manager_bind.includes(":") ? `[${plan.manager_bind}]` : plan.manager_bind}:${plan.manager_port}`);
    fact("Exporters", `${plan.exporter_bind} · ports ${plan.exporter_port_range.join("–")}`);
    fact("Consoles", `${plan.console_bind} · ports ${plan.console_port_range.join("–")}`);
    fact("Certificate", plan.certificate_action === "preserve" ?
      "Archived certificate; verify client trust." : "New self-signed certificate; update browser and Prometheus trust.");
    if (replacementSelected) {
      fact("Address replacement", "All listeners and published URLs use the selected IP; archived DNS is removed.");
      if (plan.manager_bind === "::1" || plan.manager_bind.startsWith("127.")) target.append(node("p",
        "Loopback selected: remote browsers, Prometheus, and consoles cannot connect.", "warning"));
    }
    details.append(node("p", `Host-only recovery candidate https://localhost:${plan.manager_port}`));
  } else {
    fact("Adds", `${plan.server_count} servers and local data to this empty installation`);
    fact("Keeps", "Destination users, network, certificates, and fleet settings");
    fact("Manager", plan.destination_manager_origin || "Unavailable");
    fact("Exporter ports", `${plan.server_count} needed / ${plan.destination_capacity} available · ${plan.destination_exporter_range.join("–")}`);
    fact("Console ports", plan.destination_console_range.join("–"));
    fact("BMC trust", `Source: ${plan.source_bmc_ca_custom ? "custom CA" : "system roots"} · Destination: ${plan.destination_bmc_ca_custom ? "custom CA" : "system roots"}${plan.bmc_trust_match ? "" : " · Mismatch"}`);
    if (plan.bmc_trust_gap) target.append(node("p", plan.source_bmc_ca_custom ?
      "Restore blocked: install the source BMC CA in Security, then preview again." :
      "Restore blocked: clear the custom BMC CA in Security, then preview again.", "warning"));
    if (replacementSelected) target.append(node("p", "Address replacement applies only to full restores.", "muted"));
    const list = node("ul");
    for (const port of plan.mapping) list.append(node("li", `${port.name}: exporter ${port.source_exporter_port} → ${port.exporter_port}; console ${port.console_port}`));
    target.append(list);
  }
  const prometheus = plan.prometheus;
  if (prometheus?.managed) {
    const history = prometheus.history;
    fact("Prometheus history", history.bytes ? `${history.bytes.toLocaleString()} bytes` : "Empty incoming history");
    if (history.min_time_ms != null && history.max_time_ms != null)
      fact("History period", `${new Date(history.min_time_ms).toLocaleString()} – ${new Date(history.max_time_ms).toLocaleString()}`);
    fact("Prometheus", `${prometheus.settings.enabled ? "Enabled" : "Disabled"} · ${prometheus.settings_action === "replace" ? "settings replaced" : "destination settings preserved"}`);
    fact("History outcome", manifest.scope === "full" ?
      (prometheus.archived_managed ? "Replaces destination Prometheus history" : "Replaces destination history with an empty database and default settings") :
      "Adds all archived servers’ history; preserves destination history");
    fact("Required free space", `At least ${prometheus.required_bytes.toLocaleString()} bytes during preparation and recovery`);
  } else if (prometheus) {
    fact("Prometheus", "Not installed; this archive contains no Prometheus history");
  }
  target.append(details);
  $("restore-commit-summary").textContent = manifest.scope === "full" ?
    `Full restore · ${plan.server_count} servers · ${plan.result_url}` :
    `Servers only · ${plan.server_count} servers · ${plan.destination_manager_origin || "unavailable"}`;
  $("restore-preview-status").textContent = plan.bmc_trust_gap ?
    "Archive valid · BMC trust must be updated" : "Archive valid · Preview only; no changes made";
  heading.focus();
}
function clearRestoreReview(message) {
  if (restoreCommitLocked) return;
  restorePreviewRevision++;
  restorePreviewController?.abort();
  restorePreviewController = null;
  $("restore-preview-cancel").hidden = true;
  $("restore-preview-form").removeAttribute("aria-busy");
  $("restore-preview-form").querySelector("button[type=submit]").disabled = false;
  restoreReview = null;
  $("restore-commit-form").hidden = true;
  $("restore-preview-result").replaceChildren();
  $("restore-preview-status").textContent = message;
}
function setRestorePreviewLocked(locked) {
  restoreCommitLocked = locked;
  for (const field of $("restore-preview-form").querySelectorAll("input, select, button")) field.disabled = locked;
  if (locked) $("restore-preview-cancel").hidden = true;
}
function uploadRestoreForm(path, data, onProgress, onValidating, signal = null) {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", path);
    request.withCredentials = true;
    request.timeout = 300000;
    request.setRequestHeader("X-CSRF-Token", csrf);
    request.upload.onprogress = event => {
      if (event.lengthComputable && event.total > 0)
        onProgress(Math.min(100, Math.floor(event.loaded / event.total * 100)));
    };
    request.upload.onload = onValidating;
    request.onerror = () => reject(new Error("Connection interrupted during archive upload"));
    request.onabort = () => reject(new DOMException("Archive upload was interrupted", "AbortError"));
    request.ontimeout = () => reject(new Error("Archive validation timed out. Review the connection and retry."));
    request.onload = () => resolve({status: request.status,
      ok: request.status >= 200 && request.status < 300,
      json: async () => JSON.parse(request.responseText)});
    if (signal) {
      if (signal.aborted) { reject(new DOMException("Archive upload was interrupted", "AbortError")); return; }
      signal.addEventListener("abort", () => request.abort(), {once: true});
    }
    request.send(data);
  });
}
function appendRestoreAddress(status, raw, label) {
  if (typeof raw !== "string") return;
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash ||
        !["", "/"].includes(url.pathname)) return;
    status.append(node("span", " "));
    const link = node("a", label);
    link.href = `${url.origin}/#/configuration/backup`;
    status.append(link);
  } catch { /* An invalid persisted URL must not become a browser link. */ }
}
function restoreOutcomeMessage(result) {
  if (result.status === "applied")
    return `Restore ${result.id} applied after HTTPS health checks. Verify the restored servers, console, and Prometheus.`;
  if (result.status === "reverted")
    return `Restore ${result.id} reverted: ${result.reason || "activation failed"}. The previous installation was restored and verified.`;
  return `Recovery unconfirmed for restore ${result.id}. Check service health and restore status; keep the recovery files.`;
}
function pollRestoreResult(operationId, currentUrl, proposedUrl, startedAt = Date.now()) {
  if (restorePollTimer) clearTimeout(restorePollTimer);
  const check = async () => {
    if (!identity) return;
    const status = $("restore-operation-status");
    try {
      const state = await api("/api/backup/last", "GET", null, 4000);
      if (state.last?.id === operationId) {
        restoreLastOperationId = operationId;
        $("restore-check-status").hidden = true;
        status.textContent = restoreOutcomeMessage(state.last);
        if (state.last.status === "unconfirmed") {
          setRestorePreviewLocked(true);
          restoreUnknownContext = {current: state.last.current_url || currentUrl,
            proposed: state.last.result_url || proposedUrl, priorLastId: "", startedAt: Date.now()};
          $("restore-check-status").hidden = false;
          restorePollTimer = null;
          return;
        }
        appendRestoreAddress(status, state.last.status === "applied" ?
          state.last.result_url || proposedUrl : state.last.current_url || currentUrl,
          state.last.status === "applied" ? "Open the restored manager" : "Open the previous manager");
        restorePollTimer = null;
        setRestorePreviewLocked(false);
        return;
      }
      if (state.pending?.id === operationId) {
        const phase = {queued: "queued for supervisor restart", applying: "applying the reviewed data",
          "checking-https": "checking HTTPS manager and exporter listeners"}[state.pending.status] || state.pending.status;
        status.textContent = `Restore ${operationId} is ${phase}. Connection interruptions are expected; this is not a final result.`;
        appendRestoreAddress(status, state.pending.result_url || proposedUrl,
          "Try the proposed HTTPS address after restart");
      } else {
        status.textContent = `Restore ${operationId} has no final result yet. Check ${currentUrl}, then ${proposedUrl}; sign in and inspect Restore status before retrying.`;
        appendRestoreAddress(status, proposedUrl, "Try the proposed HTTPS address");
      }
    } catch {
      if (!identity) return;
      status.textContent = `Connection interrupted while checking restore ${operationId}. Check ${currentUrl}, then ${proposedUrl}; sign in and inspect Restore status before retrying.`;
      appendRestoreAddress(status, proposedUrl, "Try the proposed HTTPS address");
    }
    if (Date.now() - startedAt < 120000 && identity) restorePollTimer = setTimeout(check, 2500);
    else {
      restorePollTimer = null;
      if (identity) status.textContent = `Restore ${operationId} is still unconfirmed after two minutes. Check ${currentUrl}, then ${proposedUrl}; sign in and inspect the persisted Restore status before retrying.`;
      if (identity) appendRestoreAddress(status, proposedUrl, "Try the proposed HTTPS address");
    }
  };
  restorePollTimer = setTimeout(check, 1000);
}
async function recoverUnconfirmedRestore() {
  const context = restoreUnknownContext;
  if (!context || !identity) return;
  if (restorePollTimer) clearTimeout(restorePollTimer);
  restorePollTimer = null;
  const button = $("restore-check-status");
  button.disabled = true;
  const status = $("restore-operation-status");
  status.textContent = "Checking the persisted restore status…";
  const retry = () => {
    if (restoreUnknownContext === context && identity && Date.now() - context.startedAt < 120000)
      restorePollTimer = setTimeout(recoverUnconfirmedRestore, 2500);
  };
  try {
    const state = await api("/api/backup/last", "GET", null, 4000);
    if (restoreUnknownContext !== context || !identity) return;
    if (state.pending?.id) {
      restoreUnknownContext = null;
      $("restore-check-status").hidden = true;
      status.textContent = `The installation is restoring operation ${state.pending.id}. This does not yet prove completion. ` +
        `Current/rollback URL: ${state.pending.current_url || context.current}. ` +
        `Proposed URL: ${state.pending.result_url || context.proposed}.`;
      appendRestoreAddress(status, state.pending.result_url || context.proposed,
        "Try the proposed HTTPS address after restart");
      pollRestoreResult(state.pending.id, state.pending.current_url || context.current,
        state.pending.result_url || context.proposed);
    } else if (state.last?.id && state.last.id !== context.priorLastId) {
      restoreUnknownContext = null;
      $("restore-check-status").hidden = true;
      restoreLastOperationId = state.last.id;
      status.textContent = restoreOutcomeMessage(state.last);
      if (state.last.status === "unconfirmed") {
        restoreUnknownContext = context;
        $("restore-check-status").hidden = false;
        setRestorePreviewLocked(true);
        return;
      }
      appendRestoreAddress(status, state.last.status === "applied" ?
        state.last.result_url || context.proposed : state.last.current_url || context.current,
        state.last.status === "applied" ? "Open the restored manager" : "Open the previous manager");
      setRestorePreviewLocked(false);
    } else {
      status.textContent = `No new restore operation is recorded yet. The submission remains unconfirmed. ` +
        `Check status again; if no operation appears after validation finishes, reload and preview the archive before retrying. ` +
        `Current URL: ${context.current}. Proposed URL: ${context.proposed}.`;
      appendRestoreAddress(status, context.proposed, "Try the proposed HTTPS address");
      retry();
    }
  } catch {
    if (restoreUnknownContext !== context || !identity) return;
    status.textContent = `Restore status could not be checked. Check ${context.current}, then ${context.proposed}; ` +
      "sign in and use Check restore status before retrying.";
    appendRestoreAddress(status, context.proposed, "Try the proposed HTTPS address");
    retry();
  } finally {
    button.disabled = false;
  }
}
$("restore-check-status").addEventListener("click", recoverUnconfirmedRestore);
for (const eventName of ["change", "input"]) $("restore-preview-form").addEventListener(eventName, () => {
  clearRestoreReview("Preview cleared because the selected archive, address, or passphrase changed.");
});
$("restore-preview-cancel").addEventListener("click", () => {
  clearRestoreReview("Preview canceled; no installation data changed.");
  $("restore-preview-form").elements.namedItem("passphrase").value = "";
});
$("restore-preview-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (restoreCommitLocked) return;
  const form = event.target;
  const archive = form.elements.namedItem("archive").files?.[0];
  if (!archive) return;
  const data = new FormData();
  data.append("archive", archive);
  data.append("passphrase", form.elements.namedItem("passphrase").value);
  const replacement = form.elements.namedItem("replacement_address").value;
  if (replacement) data.append("replacement_address", replacement);
  configError("restore-preview-error");
  const result = $("restore-preview-result"); result.replaceChildren();
  $("restore-preview-status").textContent = "Uploading and validating encrypted archive…";
  restorePreviewController?.abort();
  const controller = new AbortController();
  restorePreviewController = controller;
  const revision = ++restorePreviewRevision;
  $("restore-preview-cancel").hidden = false;
  form.setAttribute("aria-busy", "true");
  const button = form.querySelector("button[type=submit]"); button.disabled = true;
  const requestEpoch = authEpoch;
  try {
    const response = await uploadRestoreForm("/api/backup/preview", data,
      percent => { if (revision === restorePreviewRevision) $("restore-preview-status").textContent = `Uploading encrypted archive… ${percent}%`; },
      () => { if (revision === restorePreviewRevision) $("restore-preview-status").textContent = "Validating archive and destination on the manager…"; },
      controller.signal);
    if (revision !== restorePreviewRevision || controller.signal.aborted) return;
    if (response.status === 401 && identity) showLogin("Session ended. Sign in and upload the archive again.");
    const body = await response.json().catch(() => ({}));
    if (revision !== restorePreviewRevision || controller.signal.aborted) return;
    if (response.status === 403 && body.detail === "Invalid CSRF token" && identity) showLogin("Session changed. Sign in and upload the archive again.");
    if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : `Preview failed (${response.status})`);
    if (requestEpoch !== authEpoch || !identity) throw new Error("Session changed during preview. Sign in and upload again.");
    restoreReview = {archive, digest: body.archive_sha256, plan: body.plan, replacement};
    renderRestorePreview(body.manifest, body.plan, body.archive_sha256, Boolean(replacement));
    $("restore-commit-form").hidden = Boolean(body.plan.bmc_trust_gap);
  } catch (error) {
    if (revision !== restorePreviewRevision) return;
    restoreReview = null;
    $("restore-commit-form").hidden = true;
    result.replaceChildren();
    $("restore-preview-status").textContent = error.name === "AbortError" ?
      "Preview canceled; no installation data changed." : "Preview failed; no installation data changed.";
    if (error.name !== "AbortError") configError("restore-preview-error", error.message || "Preview failed. Retry after checking the manager connection.");
  } finally {
    if (restorePreviewController === controller) {
      restorePreviewController = null;
      form.elements.namedItem("passphrase").value = "";
      form.removeAttribute("aria-busy");
      $("restore-preview-cancel").hidden = true;
      button.disabled = false;
    }
  }
});
$("restore-commit-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (!restoreReview) return;
  const form = event.target;
  if (form.elements.namedItem("confirmation").value !== "RESTORE") {
    configError("restore-operation-error", "Type RESTORE to confirm this reviewed restore.");
    return;
  }
  setRestorePreviewLocked(true);
  const button = form.querySelector("button[type=submit]"); button.disabled = true;
  configError("restore-operation-error");
  $("restore-operation-status").textContent = "Uploading reviewed archive and preparing the supervised restore…";
  const requestEpoch = authEpoch;
  const data = new FormData();
  data.append("archive", restoreReview.archive);
  data.append("passphrase", form.elements.namedItem("passphrase").value);
  data.append("archive_sha256", restoreReview.digest);
  data.append("reviewed_plan", JSON.stringify(restoreReview.plan));
  if (restoreReview.replacement) data.append("replacement_address", restoreReview.replacement);
  data.append("acknowledge_interruption", form.elements.namedItem("acknowledge_interruption").checked ? "yes" : "no");
  data.append("confirmation", form.elements.namedItem("confirmation").value);
  const fallbackCurrent = restoreReview.plan.current_url || restoreReview.plan.destination_manager_origin || location.origin;
  const fallbackProposed = restoreReview.plan.result_url || fallbackCurrent;
  const priorLastId = restoreLastOperationId;
  let responseReceived = false;
  let acceptedStatus = false;
  let acceptedId = "";
  try {
    const response = await uploadRestoreForm("/api/backup/restore", data,
      percent => { $("restore-operation-status").textContent = `Uploading reviewed archive… ${percent}%`; },
      () => { $("restore-operation-status").textContent = "Validating reviewed archive before supervisor restart…"; });
    responseReceived = true;
    acceptedStatus = response.ok;
    if (response.status === 401 && identity) showLogin("Session ended. Sign in, preview again, and confirm restore.");
    const body = await response.json().catch(() => ({}));
    if (response.status === 403 && body.detail === "Invalid CSRF token" && identity) showLogin("Session changed. Sign in and preview again.");
    if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : `Restore request failed (${response.status})`);
    acceptedId = body.operation_id || "";
    if (!acceptedId || !body.result_url) throw new Error("Restore acceptance response was incomplete");
    if (requestEpoch !== authEpoch || !identity) throw new Error("Session changed while requesting restore. Check the persisted operation status after signing in.");
    restoreReview = null; form.hidden = true;
    restoreUnknownContext = null;
    $("restore-check-status").hidden = true;
    const status = $("restore-operation-status"); status.replaceChildren();
    status.append(node("span", `Restore ${body.operation_id} accepted. The supervisor is applying and checking HTTPS. A lost connection does not confirm success. `));
    appendRestoreAddress(status, body.result_url, "Try the proposed address after the supervisor finishes");
    status.append(node("span", ` Current/rollback URL: ${fallbackCurrent}. After reconnecting, sign in and inspect this operation's persisted result before relying on the restored state.`));
    pollRestoreResult(acceptedId, fallbackCurrent, fallbackProposed);
  } catch (error) {
    if (!responseReceived || acceptedStatus || acceptedId) {
      restoreReview = null; form.hidden = true;
      restoreUnknownContext = {current: fallbackCurrent, proposed: fallbackProposed,
        priorLastId, startedAt: Date.now()};
      $("restore-check-status").hidden = false;
      $("restore-operation-status").textContent = `Outcome unconfirmed${acceptedId ? ` for restore ${acceptedId}` : ""}. Checking the persisted operation status; do not retry yet.`;
      recoverUnconfirmedRestore();
    } else {
      setRestorePreviewLocked(false);
      $("restore-operation-status").textContent = "";
      configError("restore-operation-error", error.message || "Restore request failed. Review the archive and destination before retrying.");
    }
  } finally {
    form.elements.namedItem("passphrase").value = "";
    button.disabled = false;
  }
});
$("add-user-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.target; const fields = new FormData(form);
  try {
    await api("/api/users", "POST", {username: fields.get("username"), password: fields.get("password"), role: fields.get("role")});
    form.reset(); say("User added."); await loadUsers();
  } catch (error) { say(error.message); }
});
$("close-user-password").addEventListener("click", () => $("user-password-dialog").close());
$("cancel-user-password").addEventListener("click", () => $("user-password-dialog").close());
$("user-password-dialog").addEventListener("close", () => {
  $("user-password-form").reset();
  show("user-password-error", false);
  $("user-password-form").elements.namedItem("confirmation").removeAttribute("aria-invalid");
  passwordUser = null;
});
let restartPending = false;
$("collection-log-download").addEventListener("click", async () => {
  const button = $("collection-log-download"), feedback = $("collection-log-feedback");
  if (button.disabled || identity?.role !== "admin") return;
  button.disabled = true;
  feedback.textContent = "Preparing download…";
  const controller = new AbortController(), deadline = setTimeout(() => controller.abort(), 60000);
  try {
    const response = await fetch("/api/configuration/collection-log", {credentials: "same-origin", cache: "no-store", signal: controller.signal});
    if (!response.ok || !(response.headers.get("Content-Type") || "").startsWith("application/x-ndjson"))
      throw new Error("Collection log unavailable. Try again.");
    const blob = await response.blob();
    if (blob.size > 50 * 1024 * 1024 + 4096) throw new Error("Collection log unavailable. Try again.");
    const url = URL.createObjectURL(blob), link = document.createElement("a");
    link.href = url; link.download = "c880a-collection-log.jsonl";
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    feedback.textContent = "Download started. Check browser downloads.";
  } catch { feedback.textContent = "Collection log unavailable. Try again."; }
  finally { clearTimeout(deadline); button.disabled = false; }
});
$("restart-open").addEventListener("click", () => {
  $("restart-progress").textContent = "";
  $("restart-dialog").showModal();
});
$("restart-cancel").addEventListener("click", () => { if (!restartPending) $("restart-dialog").close(); });
$("restart-dialog").addEventListener("cancel", event => { if (restartPending) event.preventDefault(); });
$("restart-confirm").addEventListener("click", async () => {
  if (restartPending || identity?.role !== "admin") return;
  restartPending = true;
  $("restart-confirm").disabled = true;
  $("restart-cancel").disabled = true;
  $("restart-progress").textContent = "Requesting restart…";
  try {
    const request = await api("/api/runtime/restart", "POST");
    const deadline = Date.now() + 90000;
    $("restart-progress").textContent = "Restarting. Waiting for the manager to reconnect…";
    while (Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      try {
        const current = await api("/api/runtime");
        if (current.boot_id !== request.boot_id) {
          $("restart-progress").textContent = "Manager is back. Restoring your view…";
          window.location.reload();
          return;
        }
      } catch { /* The expected connection interruption is not a failure. */ }
    }
    $("restart-progress").textContent = "The manager has not returned yet. Check the service and reload this page after it is available.";
  } catch (error) { $("restart-progress").textContent = error.message; }
  finally {
    restartPending = false;
    $("restart-confirm").disabled = false;
    $("restart-cancel").disabled = false;
  }
});
$("user-password-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (!passwordUser) return;
  const user = passwordUser;
  const form = event.currentTarget;
  const field = form.elements.namedItem("password");
  const confirmation = form.elements.namedItem("confirmation");
  if (field.value !== confirmation.value) {
    show("user-password-error", true);
    confirmation.setAttribute("aria-invalid", "true");
    confirmation.focus();
    return;
  }
  show("user-password-error", false);
  confirmation.removeAttribute("aria-invalid");
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const result = await api(`/api/users/${user.id}/password`, "PUT", {password: field.value});
    $("user-password-dialog").close();
    if (result.current_session_revoked) { showLogin("Password changed. Sign in again."); return; }
    say(`${user.username}'s password changed. Existing sessions were revoked.`);
  } catch (error) { say(error.message); }
  finally { submit.disabled = false; }
});
$("user-password-form").elements.namedItem("confirmation").addEventListener("input", event => {
  if (event.target.value === $("user-password-form").elements.namedItem("password").value) {
    show("user-password-error", false);
    event.target.removeAttribute("aria-invalid");
  }
});
$("detail-all-events").addEventListener("click", () => { $("server-filter").value = currentDetail || ""; location.hash = "#/events"; });
$("server-search").addEventListener("input", () => { fleetPage = 1; renderServers(); });
$("fleet-page-size").addEventListener("change", () => { fleetPage = 1; renderServers(); });
$("fleet-prev").addEventListener("click", () => { fleetPage--; renderServers(); });
$("fleet-next").addEventListener("click", () => { fleetPage++; renderServers(); });
$("refresh-events").addEventListener("click", async () => { try { await loadEvents(); say("Events refreshed."); } catch (error) { say(error.message); } });
$("server-filter").addEventListener("change", () => loadEvents().catch(error => say(error.message)));
$("close-event").addEventListener("click", () => $("event-dialog").close());
$("metrics-refresh").addEventListener("click", () => {
  if (!currentDetail) return;
  loadServerLive(currentDetail).catch(error => say(error.message));
  loadMetricCatalog(currentDetail).catch(error => say(error.message));
});
$("metric-catalog-retry").addEventListener("click", () => { if (currentDetail) loadMetricCatalog(currentDetail); });
$("temperature-search").addEventListener("input", () => renderTemperatureGrid(liveReadings.get(currentDetail)));
$("metric-range").addEventListener("change", () => { if (currentMetric) showMetricHistory(currentMetric); });
$("close-metric-drawer").addEventListener("click", () => $("metric-drawer").close());
$("metric-drawer").addEventListener("close", () => { currentMetric = null; chartRequest++; chartSignature = ""; });
let metricSearchTimer;
$("metric-search").addEventListener("input", () => {
  clearTimeout(metricSearchTimer);
  metricSearchTimer = setTimeout(() => { if (currentDetail) loadMetricCatalog(currentDetail).catch(error => say(error.message)); }, 250);
});
let lastActivityTouch = 0;
function touchOnUserActivity(event) {
  if (!event.isTrusted || connectionLost || $("dashboard").hidden || document.visibilityState !== "visible") return;
  if (Date.now() - lastActivityTouch < 60000) return;
  lastActivityTouch = Date.now();
  api("/api/session").catch(() => {});
}
document.addEventListener("pointerdown", touchOnUserActivity, {passive: true});
document.addEventListener("keydown", touchOnUserActivity, {passive: true});
document.addEventListener("scroll", touchOnUserActivity, {capture: true, passive: true});

async function probeManagerHealth() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch("/health", {cache: "no-store", credentials: "same-origin", signal: controller.signal});
    if (!response.ok || !response.headers.get("content-type")?.includes("application/json")) return false;
    const result = await response.json();
    return result && result.status === "ok";
  } catch { return false; }
  finally { clearTimeout(timer); }
}

function showConnectionLost() {
  if (connectionLost || connectionClosed) return;
  connectionLost = true;
  document.body.classList.add("connection-lost");
  $("connection-message").textContent = `This browser cannot reach the manager at ${location.origin}.`;
  $("connection-status").textContent = "";
  $("connection-dialog").showModal();
  $("connection-title").focus();
}

const editedConfigurationFields = new WeakSet();
for (const eventName of ["input", "change"]) {
  $("configuration-page").addEventListener(eventName, event => {
    if (event.target.matches("input, select, textarea")) editedConfigurationFields.add(event.target);
  });
}

async function refreshConfigurationAfterRecovery() {
  if (location.hash === "#/configuration/prometheus") { await prometheusView.refresh(); return; }
  const view = document.querySelector("#configuration-page .config-view:not([hidden])");
  const edits = [...(view?.querySelectorAll("input, select, textarea") || [])]
    .filter(field => editedConfigurationFields.has(field) && field.type !== "file")
    .map(field => ({field, value: field.value, checked: field.checked}));
  try { await loadConfiguration(); }
  finally {
    for (const {field, value, checked} of edits) {
      if (field.isConnected) {
        field.value = value;
        if (field.type === "checkbox" || field.type === "radio") field.checked = checked;
      }
    }
    if (location.hash === "#/configuration/application") renderDeploymentImpact();
  }
}

async function checkManagerConnection() {
  if (connectionCheckRunning || connectionLost || connectionClosed || !identity ||
      $("dashboard").hidden || document.visibilityState !== "visible" ||
      restartPending || deploymentWatchers || restoreCommitLocked || restoreUnknownContext) return;
  connectionCheckRunning = true;
  try {
    if (await probeManagerHealth()) connectionFailures = 0;
    else if (++connectionFailures >= 2) showConnectionLost();
  } finally { connectionCheckRunning = false; }
}

async function recoverManagerConnection() {
  const button = $("connection-retry");
  button.disabled = true;
  $("connection-status").textContent = "Checking connection…";
  try {
    if (!await probeManagerHealth()) {
      $("connection-status").textContent = "Still unreachable. Retry when the connection returns.";
      return;
    }
    await refreshBuildInfo();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    let response;
    try {
      response = await fetch("/api/session?observe=1", {cache: "no-store", credentials: "same-origin", signal: controller.signal});
    } finally { clearTimeout(timer); }
    if (response.status === 401) {
      connectionLost = false;
      connectionFailures = 0;
      document.body.classList.remove("connection-lost");
      $("connection-dialog").close();
      showLogin("Session ended. Sign in to continue.");
      return;
    }
    if (!response.ok || !response.headers.get("content-type")?.includes("application/json"))
      throw new Error("Session check failed");
    const current = await response.json();
    if (!current || typeof current.csrf !== "string" || typeof current.username !== "string")
      throw new Error("Session check failed");
    connectionLost = false;
    connectionFailures = 0;
    if (current.csrf !== csrf || current.username !== identity?.username || current.role !== identity?.role ||
        current.password_change_required) {
      document.body.classList.remove("connection-lost");
      $("connection-dialog").close();
      await resumeFromCookie(current);
      return;
    }
    // Keep existing form elements in place, including unsaved edits and open dialogs.
    await loadServers();
    if (location.hash === "#/events") await loadEvents();
    else if (location.hash.startsWith("#/configuration/")) await refreshConfigurationAfterRecovery();
    else if (/^#\/servers\/[a-f0-9]{32}$/.test(location.hash) && currentDetail)
      showDetail(currentDetail).catch(error => say(error.message));
    else if (location.hash.endsWith("/inventory") && currentDetail) await loadInventory(currentDetail);
    else if (location.hash.endsWith("/metrics") && currentDetail) {
      await loadServerLive(currentDetail);
      await loadMetricCatalog(currentDetail);
    }
    document.body.classList.remove("connection-lost");
    $("connection-dialog").close();
    connectionClosed = false;
    refreshHostResources();
  } catch {
    if (!identity) return; // api() already changed to the sign-in flow.
    connectionLost = true;
    document.body.classList.add("connection-lost");
    $("connection-status").textContent = "Still unreachable. Retry when the connection returns.";
  } finally { button.disabled = false; }
}

$("connection-dialog").addEventListener("cancel", event => event.preventDefault());
$("connection-retry").addEventListener("click", recoverManagerConnection);
$("connection-close").addEventListener("click", () => {
  connectionClosed = true;
  window.close();
  setTimeout(() => {
    if (!window.closed) {
      connectionClosed = false;
      $("connection-status").textContent = "Your browser blocked closing this tab. Close it manually.";
    }
  }, 200);
});
setInterval(checkManagerConnection, 7000);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") checkManagerConnection();
});
let sessionCheckRunning = false;
setInterval(async () => {
  if ($("dashboard").hidden || connectionLost || sessionCheckRunning) return;
  sessionCheckRunning = true;
  try {
    const current = await api("/api/session?observe=1");
    if (identity && (current.csrf !== csrf || current.username !== identity.username || current.role !== identity.role))
      await resumeFromCookie(current);
  } catch { /* api() shows the login page on authentication failure. */ }
  finally { sessionCheckRunning = false; }
}, 15000);
setInterval(refreshHostResources, 15000);
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") refreshHostResources(); });
setInterval(() => {
  if (document.visibilityState !== "visible" || $("dashboard").hidden || connectionLost) return;
  if (location.hash.endsWith("/metrics") && currentDetail) {
    loadServerLive(currentDetail).catch(error => say(error.message));
    loadMetricCatalog(currentDetail).catch(error => say(error.message));
    if ($("metric-drawer").open) refreshOpenMetricHistory().catch(() => {});
  } else if (location.hash === "#/events") {
    // Refresh SQLite-backed timeline only; this does not poll any BMC.
    loadEvents().catch(error => say(error.message));
  } else if (location.hash.endsWith("/inventory") && currentDetail) {
    loadInventory(currentDetail).catch(error => say(error.message));
  } else if (location.hash === "#/servers") {
    loadServers().catch(error => say(error.message));
  }
}, 15000);
setInterval(updateAgeLabels, 1000);
setInterval(() => { if (!connectionLost) refreshOnboardingJobs().catch(() => {}); }, 3000);
document.addEventListener("visibilitychange", updateAgeLabels);
window.addEventListener("hashchange", route);

const dialog = $("onboard-dialog");
let submittingOnboarding = false;
$("open-onboard").addEventListener("click", () => { show("onboard-error", false); dialog.showModal(); dialog.querySelector("input[name=name]").focus(); });
$("close-onboard").addEventListener("click", () => dialog.close());
$("cancel-onboard").addEventListener("click", () => dialog.close());
$("onboard-form").addEventListener("submit", async event => {
  if (submittingOnboarding) return;
  event.preventDefault(); const form = new FormData(event.target);
  const button = event.target.querySelector("button[type=submit]"); button.disabled = true; submittingOnboarding = true;
  button.textContent = "Starting onboarding…"; show("onboard-error", false);
  try {
    await api("/api/onboarding-jobs", "POST", {name: form.get("name"), bmc_host: form.get("bmc_host"),
      bmc_port: Number(form.get("bmc_port")),
      username: form.get("username"), password: form.get("password"), insecure_bmc: form.has("insecure_bmc"),
      manager_metrics_enabled: form.has("manager_metrics_enabled")});
    event.target.reset(); dialog.close();
    location.hash = "#/servers";
    say("Onboarding started. It will continue in the background even if you close this page.", {autoDismissMs: 5000});
    await refreshOnboardingJobs();
  } catch (error) {
    if (dialog.open) { $("onboard-error").textContent = error.message; show("onboard-error", true); }
    else say(error.message);
  } finally {
    submittingOnboarding = false; button.disabled = false; button.textContent = "Validate and onboard";
  }
});

initialize();
