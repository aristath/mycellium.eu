// Mycellium PWA — a thin browser face over the local server's JSON API.
// No framework: fetch + small render functions. All crypto/delivery is server-side.

const api = {
  async get(path) { return json(await fetch('/api/' + path)); },
  async post(path, body) { return json(await fetch('/api/' + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })); },
  async del(path) { return json(await fetch('/api/' + path, { method: 'DELETE' })); },
};
async function json(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
  return data;
}

const state = { status: null, tab: 'threads', open: null, online: false, seen: {}, firstScan: true, openName: null, replyTo: null };
const root = document.getElementById('app');
const esc = (s) => (s == null ? '' : String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));
const initials = (s) => (s || '?').slice(0, 2).toUpperCase();
const when = (t) => { if (!t) return ''; const d = new Date(t * 1000); return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); };

async function boot() {
  if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js').catch(() => {}); }
  await refreshStatus();
  render();
  setInterval(tick, 2000);
}

// Fire a browser notification for a new incoming message.
function notify(name, body, peer) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const n = new Notification(name || 'New message', { body: body || '', icon: '/icon.svg', tag: peer });
  n.onclick = () => { window.focus(); state.tab = 'threads'; state.open = peer; state.openName = name; render(); n.close(); };
}

// Detect newly-arrived incoming messages across all threads and notify. Seeds
// silently on the first scan so existing history doesn't spam on startup.
async function notifyNew() {
  let threads = [];
  try { threads = await api.get('threads'); } catch { return; }
  for (const t of threads) {
    if (t.timestamp > (state.seen[t.peer] || 0)) {
      const viewing = !document.hidden && state.tab === 'threads' && state.open === t.peer;
      if (!state.firstScan && !t.mine && !viewing) notify(t.name, t.last, t.peer);
      state.seen[t.peer] = t.timestamp;
    }
  }
  state.firstScan = false;
}

async function refreshStatus() {
  try { state.status = await api.get('status'); } catch { state.status = null; }
}

// Poll: drain the queue into local history, then refresh the current view.
async function tick() {
  await refreshStatus();
  if (!state.status || !state.status.handle) return;
  try { await api.post('sync'); state.online = true; } catch { state.online = false; }
  renderBar();
  await notifyNew();
  if (state.tab === 'threads' && state.open) return openThread(state.open, true);
  if (state.tab === 'groups' && state.open) return openGroup(state.open, true);
  renderContent();
}

function render() {
  const s = state.status;
  if (!s || !s.handle) return renderSignup();  // no account yet → sign up
  renderApp();                                 // fully set up
}

// A prominent warning when a required service isn't running, with the exact
// command to start it. This is what was missing when register "made no sense".
function healthBanner(s) {
  if (!s) return '';
  const down = [];
  if (!s.directory_ok) down.push(['directory', s.directory, 'mycellium-server', '8080']);
  if (!s.queue_ok) down.push(['queue', s.queue, 'mycellium-queue', '8090']);
  if (!down.length) return '';
  return `<div class="banner-warn">
    ⚠ Can't reach the <b>${down.map((d) => d[0]).join('</b> & <b>')}</b>. Registration and messaging need ${down.length > 1 ? 'them' : 'it'} running:
    ${down.map((d) => `<div><code>cargo run -p ${d[2]} -- --addr ${hostOf(d[1]) || '127.0.0.1:' + d[3]}</code></div>`).join('')}
  </div>`;
}
const hostOf = (url) => (url || '').replace(/^https?:\/\//, '');

/* ---------------- auth (username + email + one-tap verify) ---------------- */

function renderSignup() {
  root.innerHTML = `
    <div class="auth">
      <h1><img src="/icon.svg" alt=""> Mycellium</h1>
      <p class="sub muted">Pick a display name and confirm your email — that's it. No password, no seed phrase.</p>
      ${healthBanner(state.status)}
      <div class="card">
        <h2>Create your account</h2>
        <label>Display name — what people see (can repeat, like a phonebook)</label>
        <input id="name" placeholder="e.g. Mary" autocomplete="off" />
        <label>Email — your unique address; this is how people add you</label>
        <input id="email" type="email" placeholder="you@example.com" autocomplete="email" />
        <div class="error" id="err"></div>
        <div class="row" style="margin-top:12px"><button id="go">Continue</button></div>
      </div>
    </div>`;
  byId('go').onclick = async () => {
    const name = byId('name').value.trim();
    const email = byId('email').value.trim();
    if (!name) return setErr('err', 'enter a display name');
    if (!email || !email.includes('@')) return setErr('err', 'enter a valid email');
    if (state.status && !state.status.directory_ok) return setErr('err', "the directory isn't running — start it (see the warning above), then retry");
    setErr('err', ''); byId('go').disabled = true;
    try {
      const r = await api.post('signup', { name, email });
      renderVerify(r.pending, r.dev_code, email);
    } catch (e) { setErr('err', e.message); byId('go').disabled = false; }
  };
}

function renderVerify(pending, devCode, email) {
  root.innerHTML = `
    <div class="auth">
      <h1><img src="/icon.svg" alt=""> Mycellium</h1>
      <div class="card">
        <h2>Check your email</h2>
        <p class="sub muted">We sent a 6-digit code to <b>${esc(email)}</b>. Enter it to finish.</p>
        ${devCode ? `<div class="banner-warn">Dev mode (no email server): your code is <b>${esc(devCode)}</b>.</div>` : ''}
        <label>Verification code</label>
        <input id="code" inputmode="numeric" placeholder="123456" autocomplete="one-time-code" value="${devCode ? esc(devCode) : ''}" />
        <div class="error" id="err"></div>
        <div class="row" style="margin-top:12px"><button id="verify">Verify &amp; enter</button><button class="ghost" id="back">Back</button></div>
      </div>
    </div>`;
  byId('code').addEventListener('keydown', (e) => { if (e.key === 'Enter') byId('verify').click(); });
  byId('back').onclick = renderSignup;
  byId('verify').onclick = async () => {
    const code = byId('code').value.trim();
    if (!code) return setErr('err', 'enter the code');
    setErr('err', ''); byId('verify').disabled = true;
    try { await api.post('signup/confirm', { pending, code }); await refreshStatus(); render(); }
    catch (e) { setErr('err', e.message); byId('verify').disabled = false; }
  };
  // One-tap email link: poll until the server marks the claim verified.
  const poll = setInterval(async () => {
    try {
      const s = await api.post('signup/status', { pending });
      if (s.verified) { clearInterval(poll); await refreshStatus(); render(); }
    } catch {}
  }, 2000);
}
/* ---------------- app ---------------- */

function renderApp() {
  root.innerHTML = `
    <header class="bar">
      <div class="who" id="who"></div>
      <div class="spacer"></div>
      <button class="link" id="profile">Share</button>
      <span class="dot" id="dot" title="sync"></span>
    </header>
    <nav class="tabs">
      <button data-tab="threads">Chats</button>
      <button data-tab="groups">Groups</button>
      <button data-tab="contacts">Contacts</button>
    </nav>
    <div id="banner"></div>
    <main id="content"></main>`;
  root.querySelectorAll('nav.tabs button').forEach((b) => {
    b.onclick = () => { state.tab = b.dataset.tab; state.open = null; renderContent(); renderBar(); };
  });
  byId('profile').onclick = profileModal;
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission().catch(() => {});
  }
  renderBar();
  renderContent();
  tick();
}

function renderBar() {
  const s = state.status || {};
  const who = byId('who'); if (who) who.innerHTML = `${esc(s.name || '—')} <small>you</small>`;
  const dot = byId('dot'); if (dot) dot.className = 'dot' + (state.online ? ' on' : '');
  const b = byId('banner'); if (b) b.innerHTML = healthBanner(state.status);
  root.querySelectorAll('nav.tabs button').forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === state.tab));
}

function renderContent() {
  if (state.tab === 'threads') return state.open ? openThread(state.open) : renderThreads();
  if (state.tab === 'groups') return state.open ? openGroup(state.open) : renderGroups();
  if (state.tab === 'contacts') return renderContacts();
}

const content = () => byId('content');

/* ---- threads ---- */
async function renderThreads() {
  let threads = [];
  try { threads = await api.get('threads'); } catch {}
  content().innerHTML = `
    <div class="list">${threads.length ? threads.map((t) => `
      <button class="item" data-peer="${esc(t.peer)}" data-name="${esc(t.name || t.peer)}">
        <div class="avatar">${esc(initials(t.name || t.peer))}</div>
        <div class="body"><div class="title">${esc(t.name || t.peer)}</div><div class="snippet">${esc(t.last || 'No messages yet')}</div></div>
        <div class="meta">${when(t.timestamp)}</div>
      </button>`).join('') : `<div class="empty">No conversations yet.<br>Message someone by their email below.</div>`}
    </div>
    <div class="fab-row"><button id="newChat">New message</button></div>`;
  content().querySelectorAll('.item').forEach((b) => (b.onclick = () => { state.open = b.dataset.peer; openThread(b.dataset.peer, false, b.dataset.name); }));
  byId('newChat').onclick = () => promptModal('New message', "Their email", (e) => { if (e) { state.open = e.trim(); openThread(e.trim(), false, e.trim()); } });
}

async function openThread(peer, quiet, name) {
  state.open = peer;
  if (name) state.openName = name;
  const label = state.openName || peer;
  let msgs = [];
  try { msgs = await api.get('threads/' + encodeURIComponent(peer)); } catch {}
  const bubbles = renderMessages(msgs);
  content().innerHTML = `
    <div class="convo">
      <div class="head"><button class="link" id="back">‹ Chats</button><div class="avatar">${esc(initials(label))}</div><b>${esc(label)}</b></div>
      <div class="messages" id="msgs">${bubbles || '<div class="empty">No messages yet. Say hello.</div>'}</div>
      ${state.replyTo ? `<div class="reply-banner">↩ Replying <button class="link" id="cancelReply">✕</button></div>` : ''}
      <div class="composer">
        <button class="attach" id="attach" title="Attach a file">📎</button>
        <input type="file" id="file" hidden />
        <input id="msg" placeholder="Message ${esc(label)}…" autocomplete="off" /><button id="send">Send</button>
      </div>
    </div>`;
  byId('back').onclick = () => { state.open = null; state.replyTo = null; renderThreads(); };
  byId('attach').onclick = () => byId('file').click();
  byId('file').onchange = async () => {
    const f = byId('file').files[0]; if (!f) return;
    if (f.size > 256 * 1024) { alert('File too large (max 256 KB).'); byId('file').value = ''; return; }
    try {
      const data = await fileToBase64(f);
      await api.post('threads/' + encodeURIComponent(peer), { file_name: f.name, file_data: data });
    } catch (e) { alert(e.message); }
    byId('file').value = '';
    openThread(peer, true);
  };
  if (byId('cancelReply')) byId('cancelReply').onclick = () => { state.replyTo = null; openThread(peer, true); };
  const input = byId('msg');
  const send = async () => {
    const text = input.value.trim(); if (!text) return;
    input.value = '';
    const body = { message: text };
    if (state.replyTo) { body.reply_to = state.replyTo; state.replyTo = null; }
    // Optimistic: show the message instantly, reconcile on refetch.
    const box = byId('msgs');
    if (box) {
      const empty = box.querySelector('.empty'); if (empty) empty.remove();
      box.insertAdjacentHTML('beforeend', `<div class="bubble me"><div>${esc(text)}</div><div class="time">now<span class="tick">✓</span></div></div>`);
      box.scrollTop = box.scrollHeight;
    }
    try { await api.post('threads/' + encodeURIComponent(peer), body); } catch (e) { alert(e.message); }
    openThread(peer, true);
  };
  byId('send').onclick = send;
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
  // Tap a message for actions (reply, react, delete).
  content().querySelectorAll('.bubble[data-id]').forEach((b) => {
    if (b.dataset.id) b.onclick = () => msgActions(peer, b.dataset.id, b.dataset.mine === 'true');
  });
  const m = byId('msgs'); if (m) m.scrollTop = m.scrollHeight;
  if (!quiet) input.focus();
}

// Reply / react / delete on a message.
function msgActions(peer, id, mine) {
  const post = (body) => api.post('threads/' + encodeURIComponent(peer), body).then(() => openThread(peer, true)).catch((e) => alert(e.message));
  modal(`
    <h3>Message</h3>
    <div class="chips">${['👍', '❤️', '😂', '🎉', '😮', '😢'].map((e) => `<button class="chip react" data-e="${e}">${e}</button>`).join('')}</div>
    <div class="actions" style="margin-top:14px">
      <button class="ghost" data-close>Cancel</button>
      <button id="reply">Reply</button>
      ${mine ? '<button class="ghost danger" id="del">Delete</button>' : ''}
    </div>`, (close) => {
    document.querySelectorAll('.chip.react').forEach((c) => (c.onclick = () => { close(); post({ react: c.dataset.e, to: id }); }));
    byId('reply').onclick = () => { close(); state.replyTo = id; openThread(peer, true); };
    if (byId('del')) byId('del').onclick = () => { close(); post({ delete: id }); };
  });
}

// Read a File as base64 (strips the data: URL prefix).
function fileToBase64(f) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(String(r.result).split(',')[1] || '');
    r.onerror = rej;
    r.readAsDataURL(f);
  });
}

// Render a message list with day dividers and a sent tick on our own messages.
function renderMessages(msgs) {
  let html = '', lastDay = '';
  for (const m of msgs) {
    const day = dayLabel(m.timestamp);
    if (day && day !== lastDay) { html += `<div class="day-divider"><span>${esc(day)}</span></div>`; lastDay = day; }
    const tick = m.from_me ? '<span class="tick">✓</span>' : '';
    html += `<div class="bubble ${m.from_me ? 'me' : ''}" data-id="${esc(m.id || '')}" data-mine="${m.from_me}"><div>${esc(m.text)}</div><div class="time">${when(m.timestamp)}${tick}</div></div>`;
  }
  return html || '<div class="empty">No messages yet. Say hello.</div>';
}

function dayLabel(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000), now = new Date();
  const same = (a, b) => a.toDateString() === b.toDateString();
  if (same(d, now)) return 'Today';
  const y = new Date(now); y.setDate(now.getDate() - 1);
  if (same(d, y)) return 'Yesterday';
  const opts = { month: 'short', day: 'numeric' };
  if (d.getFullYear() !== now.getFullYear()) opts.year = 'numeric';
  return d.toLocaleDateString([], opts);
}

/* ---- groups ---- */
async function renderGroups() {
  let groups = [];
  try { groups = await api.get('groups'); } catch {}
  content().innerHTML = `
    <div class="list">${groups.length ? groups.map((g) => `
      <button class="item" data-id="${esc(g.id)}">
        <div class="avatar">#</div>
        <div class="body"><div class="title">${esc(g.name)}</div><div class="snippet">${g.members.length} member${g.members.length === 1 ? '' : 's'}</div></div>
      </button>`).join('') : `<div class="empty">No groups yet.</div>`}
    </div>
    <div class="fab-row"><button id="newGroup">New group</button></div>`;
  content().querySelectorAll('.item').forEach((b) => (b.onclick = () => { state.open = b.dataset.id; openGroup(b.dataset.id); }));
  byId('newGroup').onclick = newGroupModal;
}

async function openGroup(id, quiet) {
  state.open = id;
  let msgs = [], groups = [];
  try { [msgs, groups] = await Promise.all([api.get('groups/' + encodeURIComponent(id)), api.get('groups')]); } catch {}
  const g = groups.find((x) => x.id === id) || { name: id, members: [] };
  const bubbles = msgs.map((m) => `<div class="bubble ${m.mine ? 'me' : ''}"><div class="sender">${esc(m.sender)}</div><div>${esc(m.text)}</div><div class="time">${when(m.timestamp)}</div></div>`).join('');
  content().innerHTML = `
    <div class="convo">
      <div class="head"><button class="link" id="back">‹ Groups</button><div class="avatar">#</div><b>${esc(g.name)}</b><span class="meta muted">· ${g.members.length}</span></div>
      <div class="messages" id="msgs">${bubbles || '<div class="empty">No messages yet.</div>'}</div>
      <div class="composer"><input id="msg" placeholder="Message ${esc(g.name)}…" autocomplete="off" /><button id="send">Send</button></div>
    </div>`;
  byId('back').onclick = () => { state.open = null; renderGroups(); };
  const input = byId('msg');
  const send = async () => {
    const text = input.value.trim(); if (!text) return;
    input.value = '';
    try { await api.post('groups/' + encodeURIComponent(id), { message: text }); } catch (e) { alert(e.message); }
    openGroup(id, true);
  };
  byId('send').onclick = send;
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
  const m = byId('msgs'); if (m) m.scrollTop = m.scrollHeight;
  if (!quiet) input.focus();
}

function newGroupModal() {
  modal(`
    <h3>New group</h3>
    <label>Name</label><input id="gname" placeholder="e.g. team" />
    <label>Members (comma-separated handles)</label><input id="gmembers" placeholder="alice, bob" />
    <div class="error" id="err"></div>
    <div class="actions"><button class="ghost" data-close>Cancel</button><button id="create">Create</button></div>`, (close) => {
    byId('create').onclick = async () => {
      const name = byId('gname').value.trim();
      const members = byId('gmembers').value.split(',').map((s) => s.trim()).filter(Boolean);
      if (!name) return setErr('err', 'name required');
      try { await api.post('groups', { name, members }); close(); renderGroups(); }
      catch (e) { setErr('err', e.message); }
    };
  });
}

/* ---- contacts ---- */
async function renderContacts() {
  let list = [];
  try { list = await api.get('contacts'); } catch {}
  content().innerHTML = `
    <div class="list">${list.length ? list.map((c) => `
      <div class="item" data-nick="${esc(c.nickname)}">
        <div class="avatar">${esc(initials(c.nickname))}</div>
        <div class="body"><div class="title">${esc(c.nickname)}</div><div class="snippet">verified · ${(c.wallet || '').slice(0, 12)}…</div></div>
        <button class="link danger" data-remove="${esc(c.nickname)}">Remove</button>
      </div>`).join('') : `<div class="empty">No contacts yet.</div>`}
    </div>
    <div class="fab-row"><button id="addContact">Add contact</button></div>`;
  content().querySelectorAll('[data-remove]').forEach((b) => (b.onclick = async (e) => {
    e.stopPropagation();
    try { await api.del('contacts/' + encodeURIComponent(b.dataset.remove)); renderContacts(); } catch (err) { alert(err.message); }
  }));
  content().querySelectorAll('.item').forEach((row) => (row.onclick = () => {
    const nick = row.dataset.nick, c = list.find((x) => x.nickname === nick);
    if (c) { state.tab = 'threads'; state.open = c.handle; renderBar(); openThread(c.handle, false, c.nickname); }
  }));
  byId('addContact').onclick = addContactModal;
}

function addContactModal() {
  modal(`
    <h3>Add contact</h3>
    <label>Their email</label><input id="cemail" placeholder="them@example.com" />
    <label>Name (optional)</label><input id="cnick" placeholder="Bob" />
    <div class="error" id="err"></div>
    <div class="actions"><button class="ghost" data-close>Cancel</button><button id="add">Add</button></div>`, (close) => {
    byId('add').onclick = async () => {
      const email = byId('cemail').value.trim(); if (!email || !email.includes('@')) return setErr('err', 'enter a valid email');
      const nickname = byId('cnick').value.trim() || email;
      try { await api.post('contacts', { email, nickname }); close(); renderContacts(); }
      catch (e) { setErr('err', e.message); }
    };
  });
}

function profileModal() {
  const s = state.status || {};
  modal(`
    <h3>Your account</h3>
    <p class="muted" style="font-size:13px">People add you by your <b>email</b> — your unique address. Your display name can repeat; your email can't.</p>
    <label>Display name</label>
    <div class="mono-box">${esc(s.name || '')}</div>
    <label>Your email — share this so people can add you</label>
    <div class="mono-box">${esc(s.email || '—')}</div>
    <div class="actions"><button class="ghost" data-close>Close</button><button id="copy">Copy email</button></div>`, () => {
    byId('copy').onclick = async () => {
      try { await navigator.clipboard.writeText(s.email || ''); byId('copy').textContent = 'Copied ✓'; }
      catch { byId('copy').textContent = '(select to copy)'; }
    };
  });
}

/* ---- little UI helpers ---- */
function byId(id) { return document.getElementById(id); }
function setErr(id, msg) { const e = byId(id); if (e) e.textContent = msg; }
function modal(html, wire) {
  const bg = document.createElement('div');
  bg.className = 'modal-bg';
  bg.innerHTML = `<div class="modal">${html}</div>`;
  document.body.appendChild(bg);
  const close = () => bg.remove();
  bg.addEventListener('click', (e) => { if (e.target === bg || e.target.hasAttribute('data-close')) close(); });
  wire(close);
}
function promptModal(title, label, done) {
  modal(`<h3>${esc(title)}</h3><label>${esc(label)}</label><input id="pval" autocomplete="off" />
    <div class="actions"><button class="ghost" data-close>Cancel</button><button id="ok">OK</button></div>`, (close) => {
    byId('pval').focus();
    byId('ok').onclick = () => { const v = byId('pval').value; close(); done(v); };
    byId('pval').addEventListener('keydown', (e) => { if (e.key === 'Enter') { const v = byId('pval').value; close(); done(v); } });
  });
}

boot();
