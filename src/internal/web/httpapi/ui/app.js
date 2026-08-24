const $ = (selector, root = document) => root.querySelector(selector);
const csrf = () => sessionStorage.getItem("wiregate-csrf") || "";
const requestKey = () => crypto.randomUUID();
const csv = (value) => String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
const enumLabel = (value, prefix) => String(value || "unknown").replace(prefix, "").replaceAll("_", " ").toLowerCase();
const bytes = (value) => {
  const size = Number(value || 0); if (!size) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const index = Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1);
  return `${(size / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
};

async function request(path, options = {}) {
  const response = await fetch(path, options);
  const type = response.headers.get("content-type") || "";
  const body = type.includes("json") ? await response.json().catch(() => ({})) : await response.blob();
  if (!response.ok) {
    const error = new Error(body?.error || `Request failed (${response.status})`);
    error.status = response.status; throw error;
  }
  return {body, response};
}
const getJSON = async (path) => (await request(path, {headers: {Accept: "application/json"}})).body;
async function postJSON(path, value, headers = {}) {
  return (await request(path, {method: "POST", headers: {
    Accept: "application/json", "Content-Type": "application/json", ...headers,
  }, body: JSON.stringify(value)})).body;
}
const mutationHeaders = (revision) => ({
  "X-CSRF-Token": csrf(), "Idempotency-Key": requestKey(), ...(revision !== undefined ? {"If-Match": String(revision)} : {}),
});

function showAuth(message = "") {
  $("#auth-view").hidden = false; $("#app-view").hidden = true;
  $("#logout").hidden = true; $("#password").hidden = true;
  $("#agent-status").textContent = "Sign-in required"; $("#agent-status").classList.remove("online");
  $("#auth-error").textContent = message; $("#auth-error").hidden = !message;
  void refreshBootstrapVisibility();
}
function showApp() {
  $("#auth-view").hidden = true; $("#app-view").hidden = false;
  $("#logout").hidden = false; $("#password").hidden = false;
  $("#bootstrap-setup").hidden = true;
}
async function refreshBootstrapVisibility() {
  const setup = $("#bootstrap-setup"); setup.hidden = true;
  try {
    const status = await getJSON("/api/v1/auth/status");
    setup.hidden = status.bootstrap_required !== true;
  } catch {
    setup.hidden = true;
  }
}
function showFormError(form, error) {
  const target = $(".form-error", form); target.textContent = error.message; target.hidden = false;
}
function previewText(plan) {
	const warnings = (plan.issues || []).map((item) => `${item.severity}: ${item.summary}`).join("\n");
	return `${plan.textual_diff_redacted || "Confirm changes"}${warnings ? `\n\n${warnings}` : ""}`;
}
async function previewAndCommit(path, payload, revision) {
  const plan = await postJSON(path, payload, mutationHeaders(revision));
  if (!confirm(`${previewText(plan)}\n\nCommit this operation?`)) return null;
  return postJSON(`/api/v1/operations/${encodeURIComponent(plan.operation_id)}/commit`,
    {reason: payload.reason || "Confirmed in WireGate UI"}, mutationHeaders());
}

function renderPeer(peer, record) {
  const item = document.createElement("div"); item.className = "peer";
  const handshake = Number(peer.latest_handshake_at_ms) ? new Date(Number(peer.latest_handshake_at_ms)).toLocaleString() : "Never";
  item.innerHTML = `<div class="peer-main"><strong></strong><code></code><small class="allowed"></small></div>
    <span class="activity"></span><small class="traffic"></small><small class="handshake"></small><div class="peer-actions"></div>`;
  $("strong", item).textContent = peer.name || "Unnamed peer";
  $("code", item).textContent = peer.public_key;
  $(".allowed", item).textContent = (peer.allowed_ips || []).join(", ");
  $(".activity", item).textContent = `${peer.lifecycle_state || "active"} · ${peer.activity_state || "unknown"}`;
  $(".traffic", item).textContent = `↓ ${bytes(peer.transfer_rx_bytes)} · ↑ ${bytes(peer.transfer_tx_bytes)}`;
	$(".handshake", item).textContent = handshake;
	const actions = $(".peer-actions", item);
	const interfaceMode = enumLabel(record.management_mode, "MANAGEMENT_MODE_");
	const manageable = ["managed", "adopted"].includes(interfaceMode);
	if (manageable && peer.key_mode === "managed" && peer.lifecycle_state === "active") {
		actions.append(actionButton("Config", () => exportPeer(peer, "conf")), actionButton("QR", () => exportPeer(peer, "qr")));
	}
	if (manageable && peer.lifecycle_state === "active") {
		actions.append(actionButton("Edit", () => openPeerUpdate(peer, record)), actionButton("Disable", () => lifecycle(peer, record, "disable")), actionButton("Revoke", () => lifecycle(peer, record, "revoke"), true));
	} else if (manageable && peer.lifecycle_state === "disabled") {
    actions.append(actionButton("Enable", () => lifecycle(peer, record, "enable")));
  }
  return item;
}
function actionButton(label, handler, danger = false) {
  const button = document.createElement("button"); button.type = "button"; button.className = `tiny secondary${danger ? " danger" : ""}`;
  button.textContent = label; button.addEventListener("click", handler); return button;
}
async function lifecycle(peer, record, mutation) {
	if (mutation === "revoke" && !confirm("Revocation is a terminal security action, and the peer's IP addresses will be quarantined. Continue?")) return;
	try {
		if (mutation === "revoke" && !await recentPassword()) return;
    await previewAndCommit(`/api/v1/peers/${encodeURIComponent(peer.id)}/lifecycle-previews`,
      {mutation, reason: `${mutation} peer from UI`}, Number(record.revision || 0));
    await load();
  } catch (error) { alert(error.message); }
}
async function recentPassword() {
  const password = prompt("Re-enter your password to export the private key:");
  if (!password) return false;
  await postJSON("/api/v1/auth/reauth", {password}, {"X-CSRF-Token": csrf()}); return true;
}
async function exportPeer(peer, format) {
  try {
    if (!await recentPassword()) return;
    const {body, response} = await request(`/api/v1/peers/${encodeURIComponent(peer.id)}/exports`, {
      method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf(), "Idempotency-Key": requestKey()},
      body: JSON.stringify({format}),
    });
    downloadBlob(body, response.headers.get("content-disposition"), `${peer.name}.${format === "qr" ? "png" : "conf"}`);
  } catch (error) { alert(error.message); }
}
function downloadBlob(blob, disposition, fallback) {
  const match = /filename="([^"]+)"/.exec(disposition || ""); const link = document.createElement("a");
  link.href = URL.createObjectURL(blob); link.download = match?.[1] || fallback; link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

async function renderInterface(record) {
  const fragment = $("#interface-template").content.cloneNode(true); const card = $(".interface-card", fragment);
  $(".interface-name", card).textContent = record.name;
  $(".interface-addresses", card).textContent = (record.addresses || []).map((item) => `${item.address}/${item.prefix_length}`).join(", ") || "No host address";
  $(".mode", card).textContent = enumLabel(record.management_mode, "MANAGEMENT_MODE_");
  $(".backend", card).textContent = enumLabel(record.backend, "INTERFACE_BACKEND_");
  $(".runtime", card).textContent = record.runtime_present ? `active · ${record.service_state || "runtime"}` : "inactive";
  $(".config", card).textContent = record.config_present ? `revision ${record.revision || 0}` : "unavailable";
  $(".drift", card).textContent = enumLabel(record.drift_state, "DRIFT_STATE_");
  $(".peer-total", card).textContent = String(record.peer_count || 0);
	const mode = enumLabel(record.management_mode, "MANAGEMENT_MODE_");
	const backend = enumLabel(record.backend, "INTERFACE_BACKEND_");
	$(".add-peer", card).hidden = mode !== "adopted";
	$(".add-peer", card).addEventListener("click", () => openPeer(record));
	$(".adopt-interface", card).hidden = !(mode === "observed" && backend === "wg quick" && record.config_present);
	$(".adopt-interface", card).addEventListener("click", () => adoptInterface(record));
  const container = $(".peers", card);
  try {
    const response = await getJSON(`/api/v1/interfaces/${encodeURIComponent(record.id)}/peers`);
    if (!(response.peers || []).length) { container.textContent = "No peers"; container.classList.add("empty"); }
    else response.peers.forEach((peer) => container.append(renderPeer(peer, record)));
  } catch (error) { container.textContent = error.message; container.classList.add("empty"); }
  return fragment;
}

async function load() {
  const error = $("#error"), list = $("#interfaces"); error.hidden = true; list.replaceChildren();
  $("#agent-status").textContent = "Connecting…";
  try {
    const [agentResponse, interfaceResponse] = await Promise.all([getJSON("/api/v1/agent"), getJSON("/api/v1/interfaces")]);
    const interfaces = interfaceResponse.interfaces || [];
    $("#agent-status").textContent = "Agent connected"; $("#agent-status").classList.add("online");
    $("#gateway").textContent = agentResponse.agent?.hostname || agentResponse.agent?.gateway_id || "Local";
    $("#interface-count").textContent = String(interfaces.length);
    $("#peer-count").textContent = String(interfaces.reduce((total, item) => total + Number(item.peer_count || 0), 0));
    for (const record of interfaces) list.append(await renderInterface(record));
		if (!interfaces.length) list.innerHTML = '<div class="empty-state">No existing WireGuard interfaces were detected on this host.</div>';
  } catch (loadError) {
    if (loadError.status === 401) return showAuth();
    $("#agent-status").textContent = "Agent unavailable"; $("#agent-status").classList.remove("online");
    error.textContent = loadError.message; error.hidden = false;
  }
}

async function adoptInterface(record) {
	const reason = prompt(`WireGate will adopt ${record.name} without rewriting its configuration file. Enter a reason:`, "Adopt existing WireGuard interface");
	if (!reason) return;
	try {
		const result = await previewAndCommit(`/api/v1/interfaces/${encodeURIComponent(record.id)}/adoption-previews`, {reason}, Number(record.revision || 0));
		if (result) await load();
	} catch (error) { alert(error.message); }
}

function openPeer(record) {
  const form = $("#peer-form"); form.reset(); form.interface_id.value = record.id; form.revision.value = record.revision || 0;
  form.endpoint_host.value = location.hostname; form.endpoint_port.value = record.listen_port || 51820;
  form.mtu.value = 1420; form.keepalive.value = 25; form.dns.value = "1.1.1.1"; form.use_preshared_key.checked = true;
  $(".form-error", form).hidden = true; $("#peer-dialog").showModal();
}

function openPeerUpdate(peer, record) {
	const form = $("#peer-update-form"); form.reset();
	form.peer_id.value = peer.id; form.revision.value = record.revision || 0;
	form.name.value = peer.name || "";
	form.server_allowed_ips.value = (peer.allowed_ips || []).join(", ");
	form.client_routes.value = ""; form.endpoint.value = peer.endpoint || "";
	form.keepalive.value = peer.persistent_keepalive_seconds || 0;
	$(".form-error", form).hidden = true; $("#peer-update-dialog").showModal();
}
$("#peer-form select[name=key_mode]").addEventListener("change", (event) => {
  const external = event.target.value === "external"; $(".external-key", $("#peer-form")).hidden = !external;
  $("#peer-form [name=external_public_key]").required = external;
});
$("#peer-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget, value = Object.fromEntries(new FormData(form));
  const payload = {name: value.name, key_mode: value.key_mode, external_public_key: value.external_public_key || "",
    server_allowed_ips: csv(value.server_allowed_ips), client_routes: csv(value.client_routes), dns: csv(value.dns),
    mtu: Number(value.mtu || 0), endpoint_host: value.endpoint_host, endpoint_port: Number(value.endpoint_port),
    persistent_keepalive_seconds: Number(value.keepalive || 0), use_preshared_key: form.use_preshared_key.checked, reason: value.reason};
  try {
    const result = await previewAndCommit(`/api/v1/interfaces/${encodeURIComponent(value.interface_id)}/peer-previews`, payload, Number(value.revision));
    if (!result) return; $("#peer-dialog").close(); await load();
    if (result.one_time_token && confirm("The one-time profile is ready. Download it now? It cannot be downloaded again.")) {
      if (!await recentPassword()) return;
      const {body, response} = await request("/api/v1/artifacts/consume", {method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf()},
        body: JSON.stringify({format: "conf", token: result.one_time_token})});
      downloadBlob(body, response.headers.get("content-disposition"), `${payload.name}.conf`);
    }
  } catch (error) { showFormError(form, error); }
});

$("#peer-update-form").addEventListener("submit", async (event) => {
	event.preventDefault(); const form = event.currentTarget, value = Object.fromEntries(new FormData(form));
	const payload = {name: value.name, server_allowed_ips: csv(value.server_allowed_ips),
		client_routes: csv(value.client_routes), endpoint: value.endpoint || "",
		persistent_keepalive_seconds: Number(value.keepalive || 0), reason: value.reason};
	try {
		const result = await previewAndCommit(`/api/v1/peers/${encodeURIComponent(value.peer_id)}/update-previews`, payload, Number(value.revision));
		if (!result) return; $("#peer-update-dialog").close(); await load();
	} catch (error) { showFormError(form, error); }
});

$("#interface-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget, value = Object.fromEntries(new FormData(form));
  const payload = {name: value.name, interface_addresses: [value.address], listen_port: Number(value.listen_port),
    deployment_profile: value.deployment_profile, firewall_mode: value.firewall_mode, lan_cidrs: csv(value.lan_cidrs),
    egress_device: value.egress_device || "", auto_start: form.auto_start.checked, reason: value.reason};
  try { const result = await previewAndCommit("/api/v1/interfaces/previews", payload); if (!result) return;
    $("#interface-dialog").close(); await load();
  } catch (error) { showFormError(form, error); }
});
$("#reload").addEventListener("click", load);
$("#password").addEventListener("click", () => $("#password-dialog").showModal());
$("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget, values = Object.fromEntries(new FormData(form));
  try { await postJSON("/api/v1/auth/password", values, {"X-CSRF-Token": csrf()}); form.reset(); $("#password-dialog").close(); alert("Password changed."); }
  catch (error) { showFormError(form, error); }
});
$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const values = Object.fromEntries(new FormData(event.currentTarget));
  try { const result = await postJSON("/api/v1/auth/login", values); sessionStorage.setItem("wiregate-csrf", result.csrf_token);
    event.currentTarget.reset(); showApp(); await load(); } catch (error) { showAuth(error.message); }
});
$("#bootstrap-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const values = Object.fromEntries(new FormData(event.currentTarget));
  try { await postJSON("/api/v1/auth/bootstrap", values); const result = await postJSON("/api/v1/auth/login", {username: values.username, password: values.password});
    sessionStorage.setItem("wiregate-csrf", result.csrf_token); event.currentTarget.reset(); showApp(); await load(); } catch (error) { showAuth(error.message); }
});
$("#logout").addEventListener("click", async () => {
  try { await postJSON("/api/v1/auth/logout", {}, {"X-CSRF-Token": csrf()}); } finally { sessionStorage.removeItem("wiregate-csrf"); showAuth(); }
});
document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
(async () => { try { await getJSON("/api/v1/auth/me"); showApp(); await load(); } catch { showAuth(); } })();
