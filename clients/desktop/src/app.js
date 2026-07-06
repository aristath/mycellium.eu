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

const state = {
  peer: null, // currently open conversation handle
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
  startPolling();
}

// Tabs
for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    for (const t of document.querySelectorAll(".tab")) t.classList.remove("active");
    tab.classList.add("active");
    const which = tab.dataset.tab;
    $("tab-conversations").classList.toggle("hidden", which !== "conversations");
    $("tab-contacts").classList.toggle("hidden", which !== "contacts");
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

async function openThread(peer) {
  state.peer = peer;
  $("thread-peer").textContent = peer;
  show($("thread-actions"));
  show($("compose"));
  await renderThread();
  refreshConversations();
}

async function renderThread() {
  if (!state.peer) return;
  try {
    const msgs = await invoke("thread", { peer: state.peer });
    const box = $("thread-msgs");
    box.innerHTML = "";
    for (const m of msgs) {
      const div = document.createElement("div");
      div.className = "msg " + (m.from_me ? "me" : "them");
      const body = document.createElement("div");
      body.textContent = m.text;
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent = fmtTime(m.sent_at) + (m.from_me ? " · " + m.delivery : "");
      div.appendChild(body);
      div.appendChild(meta);
      box.appendChild(div);
    }
    box.scrollTop = box.scrollHeight;
  } catch (e) {
    $("main-err").textContent = String(e);
  }
}

$("compose").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("compose-input");
  const text = input.value.trim();
  if (!text || !state.peer) return;
  input.value = "";
  try {
    await invoke("send_text", { peer: state.peer, text });
    await renderThread();
    refreshConversations();
  } catch (e) {
    $("main-err").textContent = String(e);
  }
});

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

// ---- Polling: pull inbound mail on a timer -------------------------------

function startPolling() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    try {
      const received = await invoke("sync");
      if (received.length > 0) {
        refreshConversations();
        if (state.peer && received.some((m) => m.thread === state.peer)) {
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
