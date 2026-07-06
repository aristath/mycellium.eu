// Mycellium desktop frontend — vanilla JS, no build step.
//
// Every user action calls a backend #[tauri::command] through the global
// `window.__TAURI__.core.invoke` bridge (enabled by `app.withGlobalTauri` in
// tauri.conf.json). No protocol/crypto/network logic lives here: the backend
// wraps the SDK; this file only renders state and forwards intent.

const invoke = window.__TAURI__.core.invoke;

const $ = (id) => document.getElementById(id);
const show = (el) => el.classList.remove("hidden");
const hide = (el) => el.classList.add("hidden");

const QUICK_REACTS = ["👍", "❤️", "😂", "🎉", "🙏"];

const state = {
  peer: null, // currently open 1:1 conversation handle (null in group mode)
  group: null, // currently open group id (null in 1:1 mode)
  replyTo: null, // message id being replied to, or null
  pollTimer: null,
};

function screen(name) {
  for (const s of document.querySelectorAll(".screen")) hide(s);
  show($("screen-" + name));
}

function fmtTime(unixSecs) {
  if (!unixSecs) return "";
  const d = new Date(unixSecs * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// ---- Setup ---------------------------------------------------------------

$("setup-btn").addEventListener("click", async () => {
  $("setup-err").textContent = "";
  const dir = $("setup-dir").value.trim();
  const queue = $("setup-queue").value.trim();
  if (!dir || !queue) {
    $("setup-err").textContent = "Both URLs are required.";
    return;
  }
  try {
    const acct = await invoke("setup", { dirUrl: dir, queueUrl: queue });
    if (acct.handle) {
      enterMain(acct);
    } else {
      screen("onboarding");
    }
  } catch (e) {
    $("setup-err").textContent = String(e);
  }
});

// ---- Onboarding ----------------------------------------------------------

$("ob-start-btn").addEventListener("click", async () => {
  $("ob-err").textContent = "";
  const handle = $("ob-handle").value.trim();
  const email = $("ob-email").value.trim();
  if (!handle || !email) {
    $("ob-err").textContent = "Handle and email are required.";
    return;
  }
  try {
    const ev = await invoke("start_email_verification", { handle, email });
    state.pending = ev.pending;
    show($("ob-confirm"));
    if (ev.dev_code) {
      $("ob-code").value = ev.dev_code; // dev-mode convenience
      $("ob-err").textContent = "Dev mode: code pre-filled.";
    }
    if (!$("ob-name").value) $("ob-name").value = handle;
  } catch (e) {
    $("ob-err").textContent = String(e);
  }
});

$("ob-confirm-btn").addEventListener("click", async () => {
  $("ob-err").textContent = "";
  const code = $("ob-code").value.trim();
  const handle = $("ob-handle").value.trim();
  const name = $("ob-name").value.trim() || handle;
  try {
    await invoke("confirm_email_verification", { pending: state.pending, code });
    const acct = await invoke("register", { handle, name });
    enterMain(acct);
  } catch (e) {
    $("ob-err").textContent = String(e);
  }
});

// ---- Main ----------------------------------------------------------------

function enterMain(acct) {
  $("me-handle").textContent = acct.handle;
  $("me-wallet").textContent = acct.wallet_address.slice(0, 16) + "…";
  screen("main");
  refreshConversations();
  refreshContacts();
  refreshGroups();
  startPolling();
}

// Tabs
const PANES = ["conversations", "groups", "contacts", "settings"];
for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    for (const t of document.querySelectorAll(".tab")) t.classList.remove("active");
    tab.classList.add("active");
    const which = tab.dataset.tab;
    for (const p of PANES) $("tab-" + p).classList.toggle("hidden", which !== p);
  });
}

async function refreshConversations() {
  try {
    const convos = await invoke("conversations");
    const ul = $("convo-list");
    ul.innerHTML = "";
    for (const c of convos) {
      const li = document.createElement("li");
      if (c.peer === state.peer) li.classList.add("active");
      li.innerHTML =
        `<div class="row1"><span class="name"></span></div>` +
        `<div class="preview"></div>`;
      li.querySelector(".name").textContent = c.display_name || c.peer;
      li.querySelector(".preview").textContent = c.last_preview || "";
      li.addEventListener("click", () => openThread(c.peer));
      ul.appendChild(li);
    }
  } catch (e) {
    $("main-err").textContent = String(e);
  }
}

async function refreshContacts() {
  try {
    const contacts = await invoke("contacts");
    const ul = $("contact-list");
    ul.innerHTML = "";
    for (const c of contacts) {
      const li = document.createElement("li");
      li.innerHTML =
        `<div class="row1"><span class="name"></span>` +
        `<span class="badge"></span></div>` +
        `<div class="preview"></div>`;
      li.querySelector(".name").textContent = c.nickname;
      li.querySelector(".preview").textContent = c.handle;
      const badge = li.querySelector(".badge");
      badge.textContent = c.trust;
      if (c.trust === "verified") badge.classList.add("verified");
      if (c.trust === "changed") badge.classList.add("changed");
      li.addEventListener("click", () => openThread(c.handle));
      ul.appendChild(li);
    }
  } catch (e) {
    $("main-err").textContent = String(e);
  }
}

$("contact-add-btn").addEventListener("click", async () => {
  $("main-err").textContent = "";
  const nickname = $("contact-nick").value.trim();
  const handle = $("contact-handle").value.trim();
  if (!nickname || !handle) return;
  try {
    await invoke("add_contact", { nickname, handle });
    $("contact-nick").value = "";
    $("contact-handle").value = "";
    refreshContacts();
  } catch (e) {
    $("main-err").textContent = String(e);
  }
});

// ---- Groups --------------------------------------------------------------

async function refreshGroups() {
  try {
    const list = await invoke("groups");
    const ul = $("group-list");
    ul.innerHTML = "";
    for (const g of list) {
      const li = document.createElement("li");
      if (g.id === state.group) li.classList.add("active");
      li.innerHTML =
        `<div class="row1"><span class="name"></span></div>` +
        `<div class="preview"></div>`;
      li.querySelector(".name").textContent = g.name || g.id;
      li.querySelector(".preview").textContent =
        g.members.length + " member" + (g.members.length === 1 ? "" : "s");
      li.addEventListener("click", () => openGroup(g.id, g.name || g.id));
      ul.appendChild(li);
    }
  } catch (e) {
    $("main-err").textContent = String(e);
  }
}

$("group-create-btn").addEventListener("click", async () => {
  $("main-err").textContent = "";
  const name = $("group-name").value.trim();
  const members = $("group-members").value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (!name) {
    $("main-err").textContent = "Group name is required.";
    return;
  }
  try {
    const id = await invoke("group_create", { name, members });
    $("group-name").value = "";
    $("group-members").value = "";
    await refreshGroups();
    openGroup(id, name);
  } catch (e) {
    $("main-err").textContent = String(e);
  }
});

$("group-leave-btn").addEventListener("click", async () => {
  if (!state.group) return;
  try {
    await invoke("group_leave", { groupId: state.group });
    state.group = null;
    $("thread-peer").textContent = "Select a conversation";
    $("thread-msgs").innerHTML = "";
    hide($("thread-actions"));
    hide($("compose"));
    refreshGroups();
  } catch (e) {
    $("main-err").textContent = String(e);
  }
});

// ---- Thread (shared by 1:1 and groups) -----------------------------------

function clearReply() {
  state.replyTo = null;
  hide($("reply-banner"));
}

async function openThread(peer) {
  state.peer = peer;
  state.group = null;
  clearReply();
  $("thread-peer").textContent = peer;
  show($("thread-actions"));
  $("safety-btn").classList.remove("hidden");
  $("verify-btn").classList.remove("hidden");
  $("group-leave-btn").classList.add("hidden");
  show($("compose"));
  await renderThread();
  refreshConversations();
}

async function openGroup(id, name) {
  state.group = id;
  state.peer = null;
  clearReply();
  $("thread-peer").textContent = name + " (group)";
  show($("thread-actions"));
  $("safety-btn").classList.add("hidden");
  $("verify-btn").classList.add("hidden");
  $("group-leave-btn").classList.remove("hidden");
  show($("compose"));
  await renderThread();
  refreshGroups();
}

async function renderThread() {
  const inGroup = !!state.group;
  if (!state.peer && !inGroup) return;
  try {
    const msgs = inGroup
      ? await invoke("group_thread", { groupId: state.group })
      : await invoke("thread", { peer: state.peer });
    const box = $("thread-msgs");
    box.innerHTML = "";
    for (const m of msgs) {
      box.appendChild(renderMessage(m, inGroup));
    }
    box.scrollTop = box.scrollHeight;
  } catch (e) {
    $("main-err").textContent = String(e);
  }
}

function renderMessage(m, inGroup) {
  const div = document.createElement("div");
  div.className = "msg " + (m.from_me ? "me" : "them");

  const body = document.createElement("div");
  body.textContent = m.text;
  div.appendChild(body);

  const meta = document.createElement("div");
  meta.className = "meta";
  const who = inGroup && !m.from_me ? m.sender + " · " : "";
  meta.textContent = who + fmtTime(m.sent_at) + (m.from_me ? " · " + m.delivery : "");
  div.appendChild(meta);

  // Per-message affordances. Reply/react/delete are 1:1 SDK operations, so
  // only offer them in 1:1 threads (groups use the compose box only).
  if (!inGroup) {
    const actions = document.createElement("div");
    actions.className = "msg-actions";

    const replyBtn = document.createElement("button");
    replyBtn.className = "mini";
    replyBtn.textContent = "Reply";
    replyBtn.addEventListener("click", () => startReply(m));
    actions.appendChild(replyBtn);

    for (const emoji of QUICK_REACTS) {
      const rb = document.createElement("button");
      rb.className = "mini emoji";
      rb.textContent = emoji;
      rb.addEventListener("click", () => reactTo(m.id, emoji));
      actions.appendChild(rb);
    }

    if (m.from_me) {
      const del = document.createElement("button");
      del.className = "mini";
      del.textContent = "Delete";
      del.addEventListener("click", () => deleteMsg(m.id));
      actions.appendChild(del);
    }

    div.appendChild(actions);
  }
  return div;
}

function startReply(m) {
  state.replyTo = m.id;
  $("reply-banner-text").textContent = "Replying to: " + m.text.slice(0, 60);
  show($("reply-banner"));
  $("compose-input").focus();
}

$("reply-cancel").addEventListener("click", clearReply);

async function reactTo(targetId, emoji) {
  if (!state.peer) return;
  try {
    await invoke("react", { peer: state.peer, target: targetId, emoji });
    await renderThread();
    refreshConversations();
  } catch (e) {
    $("main-err").textContent = String(e);
  }
}

async function deleteMsg(targetId) {
  if (!state.peer) return;
  try {
    await invoke("delete_message", { peer: state.peer, target: targetId });
    await renderThread();
    refreshConversations();
  } catch (e) {
    $("main-err").textContent = String(e);
  }
}

$("compose").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("compose-input");
  const text = input.value.trim();
  if (!text) return;
  input.value = "";
  try {
    if (state.group) {
      await invoke("group_send", { groupId: state.group, text });
    } else if (state.replyTo) {
      await invoke("reply", { peer: state.peer, replyTo: state.replyTo, text });
      clearReply();
    } else if (state.peer) {
      await invoke("send_text", { peer: state.peer, text });
    } else {
      return;
    }
    await renderThread();
    refreshConversations();
    refreshGroups();
  } catch (e) {
    $("main-err").textContent = String(e);
  }
});

// ---- Attach a file -------------------------------------------------------

$("attach-btn").addEventListener("click", () => {
  if (state.peer || state.group) $("attach-input").click();
});

$("attach-input").addEventListener("change", async (e) => {
  const file = e.target.files && e.target.files[0];
  e.target.value = ""; // allow re-selecting the same file later
  if (!file || !state.peer) {
    if (file && state.group) {
      $("main-err").textContent = "File attachments are 1:1 only for now.";
    }
    return;
  }
  try {
    const buf = await file.arrayBuffer();
    const data = Array.from(new Uint8Array(buf));
    await invoke("send_file", {
      peer: state.peer,
      name: file.name,
      mime: file.type || "application/octet-stream",
      data,
    });
    await renderThread();
    refreshConversations();
  } catch (err) {
    $("main-err").textContent = String(err);
  }
});

// ---- Verification (safety number, verify, contact cards) -----------------

$("safety-btn").addEventListener("click", async () => {
  if (!state.peer) return;
  try {
    const sn = await invoke("safety_number", { peer: state.peer });
    alert("Safety number for " + state.peer + ":\n\n" + sn);
  } catch (e) {
    $("main-err").textContent = String(e);
  }
});

$("verify-btn").addEventListener("click", async () => {
  if (!state.peer) return;
  try {
    await invoke("mark_verified", { peer: state.peer });
    refreshContacts();
    $("main-err").textContent = state.peer + " marked verified.";
  } catch (e) {
    $("main-err").textContent = String(e);
  }
});

$("card-refresh-btn").addEventListener("click", async () => {
  $("settings-msg").textContent = "";
  try {
    const card = await invoke("contact_card");
    $("my-card").value = card;
  } catch (e) {
    $("settings-msg").textContent = String(e);
  }
});

$("verify-card-btn").addEventListener("click", async () => {
  $("settings-msg").textContent = "";
  const card = $("verify-card-input").value.trim();
  if (!card) return;
  try {
    const handle = await invoke("verify_card", { card });
    $("settings-msg").textContent = "Verified " + handle + ".";
    $("verify-card-input").value = "";
    refreshContacts();
  } catch (e) {
    $("settings-msg").textContent = String(e);
  }
});

// ---- Push notifications: register a UnifiedPush endpoint ------------------

$("unifiedpush-btn").addEventListener("click", async () => {
  const endpoint = $("unifiedpush-endpoint").value.trim();
  $("settings-msg").textContent = "";
  if (!endpoint) {
    $("settings-msg").textContent = "Paste a UnifiedPush endpoint URL first.";
    return;
  }
  try {
    await invoke("register_unified_push", { endpoint });
    $("settings-msg").textContent = "UnifiedPush endpoint registered.";
  } catch (e) {
    $("settings-msg").textContent = String(e);
  }
});

// ---- Backup: export / import ---------------------------------------------

$("export-btn").addEventListener("click", async () => {
  $("settings-msg").textContent = "";
  try {
    const bytes = await invoke("export_backup");
    const blob = new Blob([new Uint8Array(bytes)], {
      type: "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "mycellium-backup.mycbak";
    a.click();
    URL.revokeObjectURL(url);
    $("settings-msg").textContent = "Backup exported (" + bytes.length + " bytes).";
  } catch (e) {
    $("settings-msg").textContent = String(e);
  }
});

$("import-input").addEventListener("change", async (e) => {
  const file = e.target.files && e.target.files[0];
  e.target.value = "";
  if (!file) return;
  $("settings-msg").textContent = "";
  try {
    const buf = await file.arrayBuffer();
    const bytes = Array.from(new Uint8Array(buf));
    await invoke("import_backup", { bytes });
    $("settings-msg").textContent = "Backup imported. Refreshing…";
    refreshConversations();
    refreshContacts();
    refreshGroups();
  } catch (err) {
    $("settings-msg").textContent = String(err);
  }
});

// ---- Polling: pull inbound mail on a timer -------------------------------

function startPolling() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    try {
      const received = await invoke("sync");
      if (received.length > 0) {
        refreshConversations();
        refreshGroups();
        const openId = state.group || state.peer;
        if (openId && received.some((m) => m.thread === openId)) {
          renderThread();
        }
      }
    } catch (_e) {
      // transient (e.g. queue unreachable) — try again next tick
    }
  }, 4000);
}

// ---- Boot ----------------------------------------------------------------

screen("setup");
