let token = localStorage.getItem('token') || '';
let me = null;
let currentChat = null;
let currentTitle = '';
let refreshTimer = null;

const $ = id => document.getElementById(id);
const api = async (url, opt = {}) => {
  const res = await fetch(url, {
    ...opt,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? {'Authorization': 'Bearer ' + token} : {}),
      ...(opt.headers || {})
    }
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || 'Request failed');
  return data;
};

function toast(message, isError = false) {
  const el = $('toast');
  el.textContent = typeof message === 'string' ? message : JSON.stringify(message, null, 2);
  el.classList.toggle('danger', !!isError);
  el.hidden = false;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.hidden = true, 4200);
}

function esc(s){return String(s ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function bytesb64(bytes){let bin=''; bytes.forEach(b=>bin+=String.fromCharCode(b)); return btoa(bin);}
function b64bytes(b64){return Uint8Array.from(atob(b64), c=>c.charCodeAt(0));}
function validUser(s){return /^[a-zA-Z0-9_.-]{3,32}$/.test(String(s||''));}

Array.from(document.querySelectorAll('.tab')).forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab,.panel').forEach(x => x.classList.remove('active'));
    btn.classList.add('active');
    $(btn.dataset.tab).classList.add('active');
  });
});

function togglePanel(id){
  const el = $(id);
  if (el) el.classList.toggle('open');
}

async function register(){
  try{
    const username = $('regUser').value.trim().toLowerCase();
    if(!validUser(username)) throw new Error('Username must be 3-32 characters using letters, numbers, dot, dash or underscore.');
    const r = await api('/api/register',{method:'POST',body:JSON.stringify({
      invite_code:$('invite').value.trim(),
      username,
      display_name:$('regName').value.trim(),
      password:$('regPass').value
    })});
    toast(r.message || 'Account created.');
  }catch(e){toast(e.message,true);}
}

async function login(){
  try{
    const r = await api('/api/login',{method:'POST',body:JSON.stringify({
      username:$('loginUser').value.trim().toLowerCase(),
      password:$('loginPass').value
    })});
    token = r.token;
    localStorage.setItem('token', token);
    me = r.user;
    await boot();
    toast('Unlocked.');
  }catch(e){toast(e.message,true);}
}

async function logout(){
  try{ if(token) await api('/api/logout',{method:'POST'}); }catch{}
  localStorage.removeItem('token');
  token=''; me=null; currentChat=null;
  clearInterval(refreshTimer);
  $('auth').hidden=false; $('app').hidden=true; $('who').textContent='Locked';
  toast('Logged out.');
}

async function boot(){
  if(!token) return;
  try{
    me = await api('/api/me');
    $('auth').hidden = true;
    $('app').hidden = false;
    $('who').textContent = `${me.display_name} · ${me.role}`;
    const isAdmin = me.role === 'admin';
    $('adminPanel').hidden = !isAdmin;
    $('adminMobileBtn').hidden = !isAdmin;
    if (isAdmin) $('adminPanel').classList.add('open');
    await loadChats();
    if('serviceWorker' in navigator) navigator.serviceWorker.register('/static/sw.js').catch(()=>{});
    clearInterval(refreshTimer);
    refreshTimer = setInterval(() => { if(currentChat) loadMsgs(false); }, 10000);
  }catch(e){
    localStorage.removeItem('token'); token='';
  }
}

async function requestNotify(){
  if(!('Notification' in window)) return toast('Notifications are not supported on this device/browser.', true);
  const p = await Notification.requestPermission();
  toast(p === 'granted' ? 'Notifications enabled for this device.' : 'Notifications not enabled.', p !== 'granted');
}

async function loadChats(){
  try{
    const rows = await api('/api/conversations');
    $('chats').innerHTML = rows.map(c => `<div class="chat ${currentChat===c.id?'active':''}" onclick='openChat(${c.id}, ${JSON.stringify(c.title)})'><div class="chat-title">${esc(c.title)}</div><div class="chat-meta">Created ${new Date(c.created_at*1000).toLocaleDateString()}</div></div>`).join('') || '<p class="muted">No chats yet. Create one below.</p>';
  }catch(e){toast(e.message,true);}
}

async function newChat(){
  try{
    const title = $('chatTitle').value.trim() || 'Private chat';
    const members = $('chatMembers').value.split(',').map(x=>x.trim().toLowerCase()).filter(Boolean);
    if(!members.length) throw new Error('Add at least one member username. Your account is added automatically.');
    const r = await api('/api/conversations',{method:'POST',body:JSON.stringify({title,member_usernames:members})});
    $('chatTitle').value=''; $('chatMembers').value='';
    toast('Secure chat created.');
    await loadChats();
    await openChat(r.id, title);
  }catch(e){toast(e.message,true);}
}

async function openChat(id,title){
  currentChat=id; currentTitle=title;
  $('chatHeading').textContent=title;
  $('chatSub').textContent='Messages decrypt locally on this device.';
  document.querySelectorAll('.chat').forEach(x=>x.classList.remove('active'));
  await loadChats();
  await loadMsgs();
}

async function keyFromPass(saltB64){
  const pass = $('passphrase').value;
  if(!pass) throw new Error('Enter the shared conversation passphrase first.');
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt:b64bytes(saltB64),iterations:250000,hash:'SHA-256'}, material, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
}

async function encryptText(text){
  if(!text.trim()) throw new Error('Message is empty.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const saltB64 = bytesb64(salt);
  const key = await keyFromPass(saltB64);
  const ct = await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, new TextEncoder().encode(text));
  return {ciphertext:bytesb64(new Uint8Array(ct)),iv:bytesb64(iv),salt:saltB64};
}

async function decryptMsg(m){
  try{
    const key = await keyFromPass(m.salt);
    const pt = await crypto.subtle.decrypt({name:'AES-GCM',iv:b64bytes(m.iv)}, key, b64bytes(m.ciphertext));
    return new TextDecoder().decode(pt);
  }catch{return '[locked — wrong or missing passphrase]';}
}

async function sendMsg(){
  if(!currentChat) return toast('Pick a chat first.', true);
  try{
    const enc = await encryptText($('msgText').value);
    await api('/api/messages',{method:'POST',body:JSON.stringify({conversation_id:currentChat,...enc})});
    $('msgText').value='';
    await loadMsgs();
    if('Notification' in window && Notification.permission==='granted') new Notification('Wurzen Secure',{body:'Encrypted message sent'});
  }catch(e){toast(e.message,true);}
}

async function loadMsgs(showErrors=true){
  if(!currentChat) return;
  try{
    const rows = await api(`/api/conversations/${currentChat}/messages`);
    let html='';
    for(const m of rows){
      const text = await decryptMsg(m);
      const mine = me && (m.sender_username === me.username);
      html += `<div class="msg ${mine?'mine':''}"><div class="meta">${esc(m.sender)} · ${new Date(m.created_at*1000).toLocaleString()}</div>${esc(text)}</div>`;
    }
    $('msgs').classList.remove('empty-state');
    $('msgs').innerHTML = html || '<div class="empty-state">No messages yet.</div>';
    $('msgs').scrollTop = $('msgs').scrollHeight;
  }catch(e){ if(showErrors) toast(e.message,true); }
}

async function makeInvite(){
  try{
    const r = await api('/api/admin/invites',{method:'POST'});
    $('inviteOut').textContent = r.code;
    try { await navigator.clipboard.writeText(r.code); toast('Invite created and copied.'); } catch { toast('Invite created.'); }
  }catch(e){toast(e.message,true);}
}

async function loadUsers(){
  try{
    const rows = await api('/api/admin/users');
    $('users').innerHTML = rows.map(u=>`<div class="user"><b>${esc(u.display_name)}</b> <span class="muted">@${esc(u.username)}</span><br><span class="${u.approved?'ok':'danger'}">${u.approved?'approved':'pending'}</span> · disabled:${u.disabled} · ${esc(u.role)}<br><button onclick='approve(${u.id})'>Approve</button><button onclick='disableUser(${u.id})'>Disable</button></div>`).join('') || '<p class="muted">No users.</p>';
  }catch(e){toast(e.message,true);}
}
async function approve(id){await api(`/api/admin/users/${id}/approve`,{method:'POST'}); toast('User approved.'); loadUsers();}
async function disableUser(id){await api(`/api/admin/users/${id}/disable`,{method:'POST'}); toast('User disabled.'); loadUsers();}
async function loadAudit(){
  try{
    const rows = await api('/api/audit');
    $('audit').innerHTML = rows.map(a=>`<div class="audit"><b>${esc(a.action)}</b><br><span class="muted">${esc(a.actor||'system')} · ${new Date(a.created_at*1000).toLocaleString()}</span><br>${esc(a.detail||'')}</div>`).join('') || '<p class="muted">No audit records.</p>';
  }catch(e){toast(e.message,true);}
}

$('msgText')?.addEventListener('keydown', e => {
  if((e.ctrlKey || e.metaKey) && e.key === 'Enter') sendMsg();
});

boot();
