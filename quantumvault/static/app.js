"use strict";

(() => {
  const CSRF = document.querySelector('meta[name="csrf-token"]').content;
  const CLIPBOARD_CLEAR_MS = 30_000;
  const REVEAL_HIDE_MS = 20_000;
  const MASK = "•".repeat(16);

  // Must match quantumvault/generator.py
  const CHARSETS = {
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    symbols: "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
  };
  const AMBIGUOUS = new Set("Il1O0o|`'\"");

  const $ = (id) => document.getElementById(id);
  const views = { setup: $("view-setup"), unlock: $("view-unlock"), dashboard: $("view-dashboard") };

  let policy = null;
  let entries = [];

  // ---------------------------------------------------------------- API

  async function api(method, path, body) {
    const opts = { method, headers: { "X-CSRF-Token": CSRF }, credentials: "same-origin" };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && path !== "/api/unlock") {
      showView("unlock");
      throw new Error("Vault is locked.");
    }
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  }

  // ---------------------------------------------------------------- views

  function showView(name) {
    for (const [key, el] of Object.entries(views)) el.classList.toggle("hidden", key !== name);
    $("lock-btn").classList.toggle("hidden", name !== "dashboard");
    const focus = { setup: "setup-password", unlock: "unlock-password", dashboard: "entry-title" }[name];
    if (focus) $(focus).focus();
    if (name !== "dashboard") {
      entries = [];
      $("entries").replaceChildren();
      $("fresh").classList.add("hidden");
    }
  }

  async function refreshStatus() {
    const status = await api("GET", "/api/status");
    policy = status.policy;
    $("min-master").textContent = policy.min_master_password_length;
    setupLengthControls();
    if (!status.initialized) showView("setup");
    else if (!status.unlocked) showView("unlock");
    else await enterDashboard();
  }

  async function enterDashboard() {
    showView("dashboard");
    await loadEntries();
  }

  // ---------------------------------------------------------------- auth

  function bindAuthForm(formId, errorId, handler) {
    $(formId).addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const button = ev.target.querySelector("button[type=submit]");
      const label = button.textContent;
      $(errorId).textContent = "";
      button.disabled = true;
      button.textContent = "Deriving key…";
      try {
        await handler();
        ev.target.reset();
        await enterDashboard();
      } catch (err) {
        $(errorId).textContent = err.message;
      } finally {
        button.disabled = false;
        button.textContent = label;
      }
    });
  }

  bindAuthForm("setup-form", "setup-error", async () => {
    const password = $("setup-password").value;
    const confirm = $("setup-confirm").value;
    if (password !== confirm) throw new Error("Passwords do not match.");
    if (password.length < policy.min_master_password_length) {
      throw new Error(`Use at least ${policy.min_master_password_length} characters.`);
    }
    await api("POST", "/api/setup", { master_password: password, confirm_password: confirm });
  });

  bindAuthForm("unlock-form", "unlock-error", async () => {
    await api("POST", "/api/unlock", { master_password: $("unlock-password").value });
  });

  $("lock-btn").addEventListener("click", async () => {
    await api("POST", "/api/lock").catch(() => {});
    showView("unlock");
  });

  // ---------------------------------------------------------------- generator options

  function currentOptions() {
    return {
      length: parseInt($("opt-length").value, 10),
      lowercase: $("opt-lowercase").checked,
      uppercase: $("opt-uppercase").checked,
      digits: $("opt-digits").checked,
      symbols: $("opt-symbols").checked,
      exclude_ambiguous: $("opt-ambiguous").checked,
    };
  }

  function setupLengthControls() {
    for (const id of ["opt-length", "opt-length-number"]) {
      const el = $(id);
      el.min = policy.min_length;
      el.max = id === "opt-length" ? 128 : policy.max_length;
      if (!el.value || el.dataset.init !== "1") {
        el.value = policy.default_length;
        el.dataset.init = "1";
      }
    }
    updateStrength();
  }

  $("opt-length").addEventListener("input", () => {
    $("opt-length-number").value = $("opt-length").value;
    updateStrength();
  });
  $("opt-length-number").addEventListener("input", () => {
    const n = parseInt($("opt-length-number").value, 10);
    if (Number.isFinite(n)) $("opt-length").value = Math.min(n, 128);
    updateStrength();
  });
  for (const id of ["opt-lowercase", "opt-uppercase", "opt-digits", "opt-symbols", "opt-ambiguous"]) {
    $(id).addEventListener("change", updateStrength);
  }

  function effectiveLength() {
    const n = parseInt($("opt-length-number").value, 10);
    return Number.isFinite(n) ? n : 0;
  }

  function classSizes(opts) {
    const sizes = [];
    for (const key of ["lowercase", "uppercase", "digits", "symbols"]) {
      if (!opts[key]) continue;
      let chars = [...CHARSETS[key]];
      if (opts.exclude_ambiguous) chars = chars.filter((c) => !AMBIGUOUS.has(c));
      if (chars.length) sizes.push(chars.length);
    }
    return sizes;
  }

  function log2Big(n) {
    if (n <= 0n) return 0;
    const bits = n.toString(2);
    const head = Number.parseInt(bits.slice(0, 53), 2);
    return Math.log2(head) + Math.max(0, bits.length - 53);
  }

  // Exact entropy of uniformly random strings that contain every chosen class
  // (inclusion-exclusion), mirroring generator._exact_entropy on the server.
  function exactEntropy(length, sizes) {
    if (!sizes.length || length < sizes.length) return 0;
    const total = sizes.reduce((a, b) => a + b, 0);
    let count = 0n;
    for (let mask = 0; mask < 1 << sizes.length; mask++) {
      let missing = 0;
      let popcount = 0;
      sizes.forEach((s, i) => {
        if (mask & (1 << i)) { missing += s; popcount++; }
      });
      const term = BigInt(total - missing) ** BigInt(length);
      count += popcount % 2 ? -term : term;
    }
    return log2Big(count);
  }

  function updateStrength() {
    if (!policy) return;
    const opts = currentOptions();
    opts.length = effectiveLength();
    const bits = exactEntropy(opts.length, classSizes(opts));
    const ok = bits >= policy.min_entropy_bits;
    const pq = bits / 2;
    $("entropy-label").textContent = `${Math.floor(bits)} bits of entropy`;
    const badge = $("pq-label");
    badge.textContent = ok ? `Quantum-safe · ${Math.floor(pq)}-bit` : `Below ${policy.min_entropy_bits}-bit floor`;
    badge.classList.toggle("bad", !ok);
    $("strength").classList.toggle("weak", !ok);
    $("meter-fill").style.width = `${Math.min(100, (bits / 512) * 100)}%`;
    $("create-btn").disabled = !ok;
  }

  // ---------------------------------------------------------------- create

  $("create-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("create-error").textContent = "";
    const options = currentOptions();
    options.length = effectiveLength();
    try {
      const data = await api("POST", "/api/entries", {
        title: $("entry-title").value,
        notes: $("entry-notes").value,
        options,
      });
      $("entry-title").value = "";
      $("entry-notes").value = "";
      $("fresh-title").textContent = data.entry.title;
      $("fresh-password").textContent = data.password;
      $("fresh").classList.remove("hidden");
      entries.unshift(data.entry);
      renderEntries();
    } catch (err) {
      $("create-error").textContent = err.message;
    }
  });

  $("fresh-copy").addEventListener("click", () => copyText($("fresh-password").textContent));
  $("fresh-close").addEventListener("click", () => {
    $("fresh-password").textContent = "";
    $("fresh").classList.add("hidden");
  });

  // ---------------------------------------------------------------- list

  async function loadEntries() {
    const data = await api("GET", "/api/entries");
    entries = data.entries.sort((a, b) => b.created_at.localeCompare(a.created_at));
    renderEntries();
  }

  $("search").addEventListener("input", renderEntries);

  function renderEntries() {
    const query = $("search").value.trim().toLowerCase();
    const visible = entries.filter(
      (e) => !query || e.title.toLowerCase().includes(query) || e.notes.toLowerCase().includes(query)
    );
    $("count").textContent = entries.length ? `(${entries.length})` : "";
    $("empty").classList.toggle("hidden", entries.length > 0);
    $("entries").replaceChildren(...visible.map(renderEntry));
  }

  function renderEntry(entry) {
    const node = $("entry-template").content.firstElementChild.cloneNode(true);
    node.dataset.id = entry.id;
    node.querySelector(".entry-title").textContent = entry.title;
    node.querySelector(".entry-notes").textContent = entry.notes;
    node.querySelector(".secret").textContent = MASK;
    node.querySelector(".meta-length").textContent = `${entry.length} characters`;
    const pq = Math.floor(entry.entropy_bits / 2);
    const badge = node.querySelector(".meta-entropy");
    badge.textContent = `${Math.floor(entry.entropy_bits)} bits · ${pq}-bit PQ`;
    badge.classList.toggle("bad", entry.entropy_bits < policy.min_entropy_bits);
    const date = new Date(entry.updated_at);
    node.querySelector(".meta-date").textContent =
      (entry.updated_at !== entry.created_at ? "Updated " : "Created ") + date.toLocaleString();

    node.querySelector(".actions").addEventListener("click", (ev) => {
      const button = ev.target.closest("button[data-action]");
      if (button) handleAction(button.dataset.action, entry, node);
    });
    return node;
  }

  async function handleAction(action, entry, node) {
    try {
      if (action === "reveal") await toggleReveal(entry, node);
      else if (action === "copy") await copyText((await fetchPassword(entry)).password);
      else if (action === "rename") startRename(entry, node);
      else if (action === "regenerate") await regenerate(entry);
      else if (action === "delete") await remove(entry);
    } catch (err) {
      toast(err.message);
    }
  }

  function fetchPassword(entry) {
    return api("GET", `/api/entries/${encodeURIComponent(entry.id)}/password`);
  }

  async function toggleReveal(entry, node) {
    const secret = node.querySelector(".secret");
    if (!secret.classList.contains("masked")) {
      hideSecret(secret);
      return;
    }
    const { password } = await fetchPassword(entry);
    secret.textContent = password;
    secret.classList.remove("masked");
    clearTimeout(secret._timer);
    secret._timer = setTimeout(() => hideSecret(secret), REVEAL_HIDE_MS);
  }

  function hideSecret(secret) {
    clearTimeout(secret._timer);
    secret.textContent = MASK;
    secret.classList.add("masked");
  }

  function startRename(entry, node) {
    const title = node.querySelector(".entry-title");
    const input = node.querySelector(".entry-title-input");
    input.value = entry.title;
    title.classList.add("hidden");
    input.classList.remove("hidden");
    input.focus();
    input.select();

    let done = false;
    const finish = async (save) => {
      if (done) return;
      done = true;
      const value = input.value.trim();
      if (save && value && value !== entry.title) {
        try {
          const data = await api("PATCH", `/api/entries/${encodeURIComponent(entry.id)}`, { title: value });
          Object.assign(entry, data.entry);
          toast("Title updated");
        } catch (err) {
          toast(err.message);
        }
      }
      renderEntries();
    };
    input.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") finish(true);
      if (ev.key === "Escape") finish(false);
    });
    input.addEventListener("blur", () => finish(true));
  }

  async function regenerate(entry) {
    const ok = await confirmDialog(
      "Generate a new password?",
      `The current password for “${entry.title}” will be replaced permanently. Make sure you update it on the site first.`,
      "Regenerate"
    );
    if (!ok) return;
    const options = currentOptions();
    options.length = effectiveLength();
    const data = await api("POST", `/api/entries/${encodeURIComponent(entry.id)}/regenerate`, { options });
    Object.assign(entry, data.entry);
    renderEntries();
    toast("New password generated");
  }

  async function remove(entry) {
    const ok = await confirmDialog(
      "Delete this password?",
      `“${entry.title}” will be removed from the vault. This cannot be undone.`,
      "Delete"
    );
    if (!ok) return;
    await api("DELETE", `/api/entries/${encodeURIComponent(entry.id)}`);
    entries = entries.filter((e) => e.id !== entry.id);
    renderEntries();
    toast("Password deleted");
  }

  // ---------------------------------------------------------------- helpers

  let clipboardTimer = null;
  async function copyText(text) {
    await navigator.clipboard.writeText(text);
    toast(`Copied — clipboard clears in ${CLIPBOARD_CLEAR_MS / 1000}s`);
    clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), CLIPBOARD_CLEAR_MS);
  }

  function confirmDialog(title, message, okLabel) {
    const dialog = $("confirm-dialog");
    $("confirm-title").textContent = title;
    $("confirm-message").textContent = message;
    $("confirm-ok").textContent = okLabel;
    dialog.returnValue = "";
    dialog.showModal();
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "ok"), { once: true });
    });
  }

  let toastTimer = null;
  function toast(message) {
    const el = $("toast");
    el.textContent = message;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
  }

  refreshStatus().catch((err) => toast(err.message));
})();
