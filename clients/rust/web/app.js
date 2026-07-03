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

const state = { status: null, tab: 'threads', open: null, online: false };
const root = document.getElementById('app');
const esc = (s) => (s == null ? '' : String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));
const initials = (s) => (s || '?').slice(0, 2).toUpperCase();
const when = (t) => { if (!t) return ''; const d = new Date(t * 1000); return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); };

async function boot() {
  if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js').catch(() => {}); }
  await refreshStatus();
  render();
  setInterval(tick, 5000);
}

async function refreshStatus() {
  try { state.status = await api.get('status'); } catch { state.status = null; }
}

// Poll: drain the queue into local history, then refresh the current view.
async function tick() {
  await refreshStatus();
  if (!state.status || !state.status.unlocked || !state.status.handle) return;
  try { await api.post('sync'); state.online = true; } catch { state.online = false; }
  renderBar();
  if (state.tab === 'threads' && state.open) return openThread(state.open, true);
  if (state.tab === 'groups' && state.open) return openGroup(state.open, true);
  renderContent();
}

function render() {
  const s = state.status;
  if (!s || !s.has_identity) return renderRegister();  // no account yet
  if (!s.unlocked) return renderLogin();               // account, needs unlock
  if (!s.handle) return renderClaimHandle(null, s.wallet); // identity but no name claimed yet
  renderApp();                                         // fully set up
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

/* ---------------- auth ---------------- */

function renderRegister() {
  root.innerHTML = `
    <div class="auth">
      <h1><img src="/icon.svg" alt=""> Mycellium</h1>
      <p class="sub muted">Create your account. Your seed phrase <b>is</b> your identity — it is generated on this device and never leaves it.</p>
      ${healthBanner(state.status)}
      <div class="card" id="step1">
        <h2>1 — Choose a passphrase</h2>
        <p class="muted" style="font-size:13px">Encrypts your identity at rest on this device.</p>
        <label>Passphrase</label>
        <input id="pass" type="password" placeholder="a strong passphrase" autocomplete="new-password" />
        <div class="error" id="err"></div>
        <div class="row" style="margin-top:12px"><button id="create">Generate identity</button></div>
        <div style="margin-top:8px"><button class="link" id="toLogin">Already have an identity? Unlock it</button>
        · <button class="link" id="toRestore">Restore from seed phrase</button></div>
      </div>
    </div>`;
  byId('create').onclick = async () => {
    const passphrase = byId('pass').value;
    if (!passphrase) return setErr('err', 'passphrase required');
    try {
      const r = await api.post('identity', { passphrase });
      await refreshStatus();
      renderClaimHandle(r.mnemonic, r.wallet);
    } catch (e) { setErr('err', e.message); }
  };
  byId('toLogin').onclick = renderLogin;
  byId('toRestore').onclick = renderRestore;
}

// Fresh registration passes the mnemonic (shown once). The resume case (identity
// exists but the name claim never completed — e.g. the directory was down) passes
// null: no seed to show, just finish claiming the name.
function renderClaimHandle(mnemonic, wallet) {
  const seedCard = mnemonic
    ? `<div class="card">
        <h2>2 — Write down your seed phrase</h2>
        <p class="muted" style="font-size:13px">These 24 words recover your account anywhere. Store them safely — anyone with them <b>is</b> you. There is no reset.</p>
        <div class="mnemonic">${esc(mnemonic)}</div>
      </div>`
    : `<p class="sub muted">Your identity is ready${wallet ? ` (<code>${esc(wallet.slice(0, 10))}…</code>)` : ''}, but the last step didn't finish. Claim your name to continue.</p>`;
  root.innerHTML = `
    <div class="auth">
      <h1><img src="/icon.svg" alt=""> Mycellium</h1>
      ${healthBanner(state.status)}
      ${seedCard}
      <div class="card">
        <h2>${mnemonic ? '3 — ' : ''}Claim your name</h2>
        <label>Handle</label>
        <input id="handle" placeholder="e.g. mary" autocomplete="off" />
        <div class="error" id="err"></div>
        <div class="row" style="margin-top:12px">
          <button id="reg">Register &amp; enter</button>
          ${mnemonic ? '' : '<button class="ghost" id="lock">Lock</button>'}
        </div>
      </div>
    </div>`;
  byId('reg').onclick = async () => {
    const handle = byId('handle').value.trim();
    if (!handle) return setErr('err', 'pick a handle');
    setErr('err', '');
    byId('reg').disabled = true;
    try { await api.post('register', { handle }); await refreshStatus(); render(); }
    catch (e) { setErr('err', e.message); byId('reg').disabled = false; }
  };
  if (byId('lock')) byId('lock').onclick = async () => { await api.post('lock').catch(() => {}); location.reload(); };
}

function renderLogin() {
  root.innerHTML = `
    <div class="auth">
      <h1><img src="/icon.svg" alt=""> Mycellium</h1>
      ${healthBanner(state.status)}
      <div class="card">
        <h2>Unlock</h2>
        <label>Passphrase</label>
        <input id="pass" type="password" autocomplete="current-password" />
        <div class="error" id="err"></div>
        <div class="row" style="margin-top:12px"><button id="go">Unlock</button></div>
        <div style="margin-top:8px"><button class="link" id="toRestore">Restore from seed phrase</button></div>
      </div>
    </div>`;
  byId('pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') byId('go').click(); });
  byId('go').onclick = async () => {
    try { await api.post('unlock', { passphrase: byId('pass').value }); await refreshStatus(); render(); }
    catch (e) { setErr('err', e.message); }
  };
  byId('toRestore').onclick = renderRestore;
}

function renderRestore() {
  root.innerHTML = `
    <div class="auth">
      <h1><img src="/icon.svg" alt=""> Mycellium</h1>
      <div class="card">
        <h2>Restore from seed phrase</h2>
        <label>24-word seed phrase</label>
        <textarea id="phrase" rows="3" placeholder="word1 word2 …"></textarea>
        <label>New passphrase (encrypts it on this device)</label>
        <input id="pass" type="password" autocomplete="new-password" />
        <div class="error" id="err"></div>
        <div class="row" style="margin-top:12px"><button id="go">Restore</button><button class="ghost" id="back">Back</button></div>
      </div>
    </div>`;
  byId('back').onclick = render;
  byId('go').onclick = async () => {
    try {
      const r = await api.post('restore', { phrase: byId('phrase').value, passphrase: byId('pass').value });
      await refreshStatus();
      // After restore, they still need a handle on this device (register/link).
      renderClaimHandle(null, (state.status && state.status.wallet) || r.wallet);
    } catch (e) { setErr('err', e.message); }
  };
}

/* ---------------- app ---------------- */

function renderApp() {
  root.innerHTML = `
    <header class="bar">
      <div class="who" id="who"></div>
      <div class="spacer"></div>
      <span class="dot" id="dot" title="sync"></span>
      <button class="link" id="lock">Lock</button>
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
  byId('lock').onclick = async () => { try { await api.post('lock'); } catch {} location.reload(); };
  renderBar();
  renderContent();
  tick();
}

function renderBar() {
  const s = state.status || {};
  const who = byId('who'); if (who) who.innerHTML = `${esc(s.handle || '—')} <small>${(s.wallet || '').slice(0, 10)}…</small>`;
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
      <button class="item" data-peer="${esc(t.peer)}">
        <div class="avatar">${esc(initials(t.peer))}</div>
        <div class="body"><div class="title">${esc(t.peer)}</div><div class="snippet">${esc(t.last || 'No messages yet')}</div></div>
        <div class="meta">${when(t.timestamp)}</div>
      </button>`).join('') : `<div class="empty">No conversations yet.<br>Start one below.</div>`}
    </div>
    <div class="fab-row"><button id="newChat">New message</button></div>`;
  content().querySelectorAll('.item').forEach((b) => (b.onclick = () => { state.open = b.dataset.peer; openThread(b.dataset.peer); }));
  byId('newChat').onclick = () => promptModal('New message', 'Recipient handle', (h) => { if (h) { state.open = h.trim(); openThread(h.trim()); } });
}

async function openThread(peer, quiet) {
  state.open = peer;
  let msgs = [];
  try { msgs = await api.get('threads/' + encodeURIComponent(peer)); } catch {}
  const bubbles = msgs.map((m) => `<div class="bubble ${m.from_me ? 'me' : ''}"><div>${esc(m.text)}</div><div class="time">${when(m.timestamp)}</div></div>`).join('');
  content().innerHTML = `
    <div class="convo">
      <div class="head"><button class="link" id="back">‹ Chats</button><div class="avatar">${esc(initials(peer))}</div><b>${esc(peer)}</b></div>
      <div class="messages" id="msgs">${bubbles || '<div class="empty">No messages yet. Say hello.</div>'}</div>
      <div class="composer"><input id="msg" placeholder="Message ${esc(peer)}…" autocomplete="off" /><button id="send">Send</button></div>
    </div>`;
  byId('back').onclick = () => { state.open = null; renderThreads(); };
  const input = byId('msg');
  const send = async () => {
    const text = input.value.trim(); if (!text) return;
    input.value = '';
    try { await api.post('threads/' + encodeURIComponent(peer), { message: text }); } catch (e) { alert(e.message); }
    openThread(peer, true);
  };
  byId('send').onclick = send;
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
  const m = byId('msgs'); if (m) m.scrollTop = m.scrollHeight;
  if (!quiet) input.focus();
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
        <div class="body"><div class="title">${esc(c.nickname)}</div><div class="snippet">${esc(c.handle)} · ${(c.wallet || '').slice(0, 12)}…</div></div>
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
    if (c) { state.tab = 'threads'; state.open = c.handle; renderBar(); openThread(c.handle); }
  }));
  byId('addContact').onclick = addContactModal;
}

function addContactModal() {
  modal(`
    <h3>Add contact</h3>
    <label>Handle</label><input id="chandle" placeholder="e.g. bob" />
    <label>Nickname (optional)</label><input id="cnick" placeholder="Bob" />
    <div class="error" id="err"></div>
    <div class="actions"><button class="ghost" data-close>Cancel</button><button id="add">Add</button></div>`, (close) => {
    byId('add').onclick = async () => {
      const handle = byId('chandle').value.trim(); if (!handle) return setErr('err', 'handle required');
      const nickname = byId('cnick').value.trim() || handle;
      try { await api.post('contacts', { handle, nickname }); close(); renderContacts(); }
      catch (e) { setErr('err', e.message); }
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
