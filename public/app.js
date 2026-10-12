const $ = s => document.querySelector(s);
let selectedGuild = null;
let guildData = null;
let logRefreshTimer = null;
const form = $('#settings-form');
const API_BASE = (window.SENTINEL_API_BASE || 'https://bot.k7devs.com').replace(/\/$/, '');
const isAdminPage = location.pathname.replace(/\/$/, '') === '/admin';
// Keep the dashboard UI on iik27.com; only API/auth requests go to bot.k7devs.com.
document.body.classList.toggle('admin-page', isAdminPage);

let dashboardToken = sessionStorage.getItem('sentinel.dashboardToken') || '';
async function api(url, options = {}) {
  const authHeaders = dashboardToken ? { Authorization: `Bearer ${dashboardToken}` } : {};
  const response = await fetch(`${API_BASE}${url}`, { credentials: 'omit', ...options, headers: { 'Content-Type': 'application/json', ...authHeaders, ...(options.headers || {}) } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
function toast(message, error = false) { const t = $('#toast'); t.textContent = message; t.classList.remove('hidden'); t.style.background = error ? '#30151c' : '#18251f'; t.style.borderColor = error ? '#7c2c3d' : '#31644c'; t.style.color = error ? '#ffc0ca' : '#b7f5d3'; setTimeout(() => t.classList.add('hidden'), 4200); }
function setBotStatus(ready) { $('#bot-status').innerHTML = `<i style="background:${ready ? 'var(--green)' : 'var(--amber)'}"></i> ${ready ? 'Bot connected' : 'Bot connecting'}`; $('#stat-bot').textContent = ready ? 'ONLINE' : 'STARTING'; }
function timeAgo(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? '' : date.toLocaleString(); }
function formatUptime(seconds) {
  const n = Math.max(0, Number(seconds) || 0);
  const days = Math.floor(n / 86400), hours = Math.floor((n % 86400) / 3600), minutes = Math.floor((n % 3600) / 60);
  return days ? `${days}d ${hours}h` : hours ? `${hours}h ${minutes}m` : `${minutes}m`;
}
async function refreshPublicStats() {
  try {
    const stats = await api('/api/public-stats');
    const servers = $('#public-stat-servers'), members = $('#public-stat-members'), protectedServers = $('#public-stat-protected'), events = $('#public-stat-events'), uptime = $('#public-stat-uptime'), updated = $('#public-stat-updated');
    if (servers) servers.textContent = Number(stats.serverCount || 0).toLocaleString();
    if (members) members.textContent = Number(stats.memberCount || 0).toLocaleString();
    if (protectedServers) protectedServers.textContent = stats.protectedServers == null ? '—' : Number(stats.protectedServers).toLocaleString();
    if (events) events.textContent = stats.eventsLast24h == null ? '—' : Number(stats.eventsLast24h).toLocaleString();
    if (uptime) uptime.textContent = stats.botReady ? formatUptime(stats.uptimeSeconds) : 'Offline';
    if (updated) updated.textContent = stats.generatedAt ? `Updated ${new Date(stats.generatedAt).toLocaleTimeString()}` : 'Live API statistics';
  } catch (error) {
    const updated = $('#public-stat-updated'); if (updated) updated.textContent = 'Statistics temporarily unavailable';
  }
}
async function init() {
  try {
    if (isAdminPage) {
      document.querySelectorAll('main > section').forEach(section => { if (!['welcome','console'].includes(section.id)) section.classList.add('hidden'); });
      const handoff = new URLSearchParams(location.search).get('code');
      if (handoff) {
        const exchange = await fetch(`${API_BASE}/auth/exchange`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: handoff }) });
        const exchangeData = await exchange.json().catch(() => ({}));
        if (!exchange.ok || !exchangeData.token) throw new Error(exchangeData.error || 'Discord sign-in handoff failed. Please sign in again.');
        dashboardToken = exchangeData.token; sessionStorage.setItem('sentinel.dashboardToken', dashboardToken);
        history.replaceState({}, document.title, '/admin');
      }
    }
    const config = await api('/api/public-config');
    const invite = $('#invite-bot');
    const inviteCta = $('#invite-cta');
    if (inviteCta) inviteCta.href = '#invite';
    if (invite) {
      if (config.inviteUrl) { invite.href = config.inviteUrl; invite.target = '_blank'; invite.rel = 'noopener noreferrer'; if (inviteCta) { inviteCta.href = config.inviteUrl; inviteCta.target = '_blank'; inviteCta.rel = 'noopener noreferrer'; } }
      else { invite.href = '#'; if (inviteCta) inviteCta.addEventListener('click', e => { e.preventDefault(); toast('Bot invite is not configured yet.', true); }); invite.addEventListener('click', e => { e.preventDefault(); toast('Bot invite is not configured yet.', true); }); }
    }
    const me = await api('/api/me'); setBotStatus(me.botReady);
    refreshPublicStats();
    if (!window.__sentinelStatsTimer) window.__sentinelStatsTimer = setInterval(refreshPublicStats, 60000);
    if (!isAdminPage) {
      $('#welcome').classList.remove('hidden');
      $('#console').classList.add('hidden');
      if (me.user) {
        $('#admin-link').textContent = 'Open owner dashboard →';
        $('#admin-link').href = 'https://iik27.com/admin';
      }
      return;
    }
    $('#welcome').classList.add('hidden');
    if (!me.user) {
      $('#welcome').classList.remove('hidden');
      $('#welcome').querySelector('h1').innerHTML = 'Owner access<br><span>required.</span>';
      $('#welcome').querySelector('.lead').textContent = 'The admin dashboard is restricted to verified Discord server owners. Invite Sentinel to your server first, then sign in to continue.';
      const actions = $('.hero-actions');
      actions.innerHTML = '';
      const signIn = document.createElement('a'); signIn.className = 'button primary'; signIn.href = `${API_BASE}/auth/login?next=%2Fadmin`; signIn.textContent = 'Sign in with Discord ↗';
      actions.append(signIn);
      return;
    }
    $('#console').classList.remove('hidden'); $('#logout').classList.remove('hidden');
    $('#signed-in-as').textContent = `Signed in as ${me.user.global_name || me.user.username} · server owner access only`;
    const data = await api('/api/guilds'); $('#stat-guilds').textContent = data.guilds.length;
    if (!data.guilds.length) {
      $('#console').classList.add('hidden');
      $('#welcome').classList.remove('hidden');
      $('#welcome').querySelector('h1').innerHTML = 'Owner access<br><span>not available.</span>';
      $('#welcome').querySelector('.lead').textContent = 'The admin dashboard is only available to owners of a Discord server where Sentinel is installed. Invite Sentinel to a server you own, then return here.';
      return;
    }
    const list = $('#guild-list'); list.innerHTML = '';
    data.guilds.forEach(g => {
      const button = document.createElement('button'); button.className = 'guild-item'; button.dataset.id = g.id;
      const avatar = document.createElement('span'); avatar.className = 'guild-avatar'; avatar.textContent = g.name.slice(0, 1).toUpperCase();
      const name = document.createElement('span'); name.textContent = g.name;
      button.append(avatar, name); button.addEventListener('click', () => loadGuild(g.id, button)); list.append(button);
    });
    if (data.guilds.length) await loadGuild(data.guilds[0].id, list.querySelector('button'));
  } catch (e) {
    if (isAdminPage) {
      document.querySelectorAll('main > section').forEach(section => { if (section.id !== 'welcome') section.classList.add('hidden'); });
      $('#welcome').classList.remove('hidden');
      $('#welcome').querySelector('h1').innerHTML = 'Dashboard<br><span>connection failed.</span>';
      $('#welcome').querySelector('.lead').textContent = `${e.message} Check the Sentinel backend, then try signing in again.`;
      const actions = $('.hero-actions'); actions.innerHTML = '';
      const signIn = document.createElement('a'); signIn.className = 'button primary'; signIn.href = `${API_BASE}/auth/login?next=%2Fadmin`; signIn.textContent = 'Sign in / reconnect with Discord ↗'; actions.append(signIn);
      toast(e.message, true);
    } else console.warn('[Sentinel] Public page initialization:', e.message);
  }
}
async function loadGuild(id, button) {
  selectedGuild = id; document.querySelectorAll('.guild-item').forEach(x => x.classList.toggle('active', x === button));
  $('#empty-state').classList.add('hidden'); $('#server-panel').classList.remove('hidden'); $('#guild-name').textContent = 'Loading…';
  try {
    guildData = await api(`/api/guilds/${id}`); const s = guildData.settings;
    $('#guild-name').textContent = guildData.guild.name; $('#stat-members').textContent = Number(guildData.guild.memberCount || 0).toLocaleString();
    $('#enabled-tag').textContent = s.lockdownActive ? 'LOCKDOWN ACTIVE' : (s.enabled ? 'ENABLED' : 'DISABLED'); $('#enabled-tag').classList.toggle('off', !s.enabled || Boolean(s.lockdownActive));
    for (const key of ['enabled','antiSpam','antiRaid','antiInvite','antiMassMention','antiNuke','antiLinks','antiCaps','antiDuplicate','antiWebhook','antiBotAdd','antiAccountAge','antiDangerousPerms','antiMassBan','antiRoleDelete','antiChannelDelete','antiGuildUpdate','autoResponse','autoBackupEnabled']) form.elements[key].checked = Boolean(s[key]);
    form.elements.securityProfile.value = s.securityProfile || 'medium';
    for (const key of ['joinThreshold','joinWindowSeconds','spamMessages','spamWindowSeconds','mentionLimit','punishment','minAccountAgeHours','autoBackupIntervalHours','backupRetention']) form.elements[key].value = s[key];
    const select = $('#log-channel'); select.innerHTML = '<option value="">No log channel selected</option>';
    guildData.channels.forEach(c => { const o = document.createElement('option'); o.value = c.id; o.textContent = `# ${c.name}`; select.append(o); }); select.value = s.logChannelId || '';
    renderEvents(guildData.events); renderBackups(guildData.backups);
  } catch (e) { toast(e.message, true); }
}
async function refreshLogs() {
  if (!selectedGuild) return;
  const root = $('#events-list');
  if (root) root.innerHTML = '<p class="muted">Loading security logs…</p>';
  const params = new URLSearchParams({ limit: '100' });
  const severity = $('#log-severity')?.value || '';
  const q = $('#log-search')?.value.trim() || '';
  if (severity) params.set('severity', severity);
  if (q) params.set('q', q);
  try {
    const result = await api(`/api/guilds/${selectedGuild}/events?${params.toString()}`);
    renderEvents(result.events || []);
  } catch (error) { if (root) root.innerHTML = `<p class="muted">${escapeHtml(error.message)}</p>`; }
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[char]));
}
function renderEvents(events) {
  const root = $('#events-list'); root.innerHTML = '';
  if (!events.length) { root.innerHTML = '<p class="muted">No security events have been recorded yet.</p>'; return; }
  events.forEach(e => { const item = document.createElement('div'); item.className = 'event'; const top = document.createElement('div'); top.className = 'event-top'; const type = document.createElement('span'); type.className = 'event-type'; type.textContent = e.type; const sev = document.createElement('span'); sev.className = `severity ${e.severity}`; sev.textContent = e.severity; top.append(type, sev); const p = document.createElement('p'); p.textContent = e.message; const time = document.createElement('time'); time.textContent = timeAgo(e.createdAt); item.append(top,p,time); root.append(item); });
}
function renderBackups(backups) {
  const root = $('#backups-list'); root.innerHTML = '';
  if (!backups.length) { root.innerHTML = '<p class="muted">No metadata backups found. Use /sentinel backup in Discord to create one.</p>'; return; }
  backups.forEach(b => { const item = document.createElement('div'); item.className = 'event'; const top = document.createElement('div'); top.className = 'event-top'; const name = document.createElement('span'); name.className = 'event-type'; name.textContent = `Backup ${String(b._id).slice(-8)}`; const time = document.createElement('time'); time.textContent = timeAgo(b.createdAt); top.append(name,time); const p = document.createElement('p'); p.textContent = `Created by Discord user ${b.createdBy}`; item.append(top,p); root.append(item); });
}
form.elements.securityProfile?.addEventListener('change', () => {
  const profile = form.elements.securityProfile.value;
  const presets = {
    low: { antiSpam:true, antiRaid:true, antiInvite:true, antiMassMention:true, antiNuke:true, antiLinks:false, antiCaps:false, antiDuplicate:false, antiWebhook:true, antiBotAdd:true, antiAccountAge:false, antiDangerousPerms:true, antiMassBan:true, antiRoleDelete:true, antiChannelDelete:true, antiGuildUpdate:true, autoResponse:false, joinThreshold:12, spamMessages:8, mentionLimit:8, punishment:'delete' },
    medium: { antiSpam:true, antiRaid:true, antiInvite:true, antiMassMention:true, antiNuke:true, antiLinks:false, antiCaps:true, antiDuplicate:true, antiWebhook:true, antiBotAdd:true, antiAccountAge:false, antiDangerousPerms:true, antiMassBan:true, antiRoleDelete:true, antiChannelDelete:true, antiGuildUpdate:true, autoResponse:true, joinThreshold:8, spamMessages:6, mentionLimit:5, punishment:'timeout' },
    high: { antiSpam:true, antiRaid:true, antiInvite:true, antiMassMention:true, antiNuke:true, antiLinks:true, antiCaps:true, antiDuplicate:true, antiWebhook:true, antiBotAdd:true, antiAccountAge:true, antiDangerousPerms:true, antiMassBan:true, antiRoleDelete:true, antiChannelDelete:true, antiGuildUpdate:true, autoResponse:true, joinThreshold:5, spamMessages:4, mentionLimit:3, punishment:'timeout' }
  }[profile];
  for (const [key, value] of Object.entries(presets)) {
    if (['joinThreshold','spamMessages','mentionLimit','punishment'].includes(key)) form.elements[key].value = value;
    else if (form.elements[key]?.type === 'checkbox') form.elements[key].checked = value;
  }
  toast(`${profile.toUpperCase()} baseline selected. Save configuration to apply it.`);
});
// Individual switches apply immediately, so the UI never appears to toggle a defense
// without persisting the change to MongoDB for the live bot handlers.
const immediateSwitches = ['enabled','autoResponse','antiSpam','antiRaid','antiInvite','antiMassMention','antiNuke','antiLinks','antiCaps','antiDuplicate','antiWebhook','antiBotAdd','antiAccountAge','antiDangerousPerms','antiMassBan','antiRoleDelete','antiChannelDelete','antiGuildUpdate','autoBackupEnabled'];
for (const key of immediateSwitches) {
  const control = form.elements[key];
  control?.addEventListener('change', async () => {
    if (!selectedGuild || !control) return;
    const desired = control.checked;
    control.disabled = true;
    try {
      await api(`/api/guilds/${selectedGuild}/settings`, { method: 'PATCH', body: JSON.stringify({ [key]: desired }) });
      $('#enabled-tag').textContent = guildData?.settings?.lockdownActive ? 'LOCKDOWN ACTIVE' : (form.elements.enabled.checked ? 'ENABLED' : 'DISABLED');
      $('#enabled-tag').classList.toggle('off', !form.elements.enabled.checked || Boolean(guildData?.settings?.lockdownActive));
      $('#save-status').textContent = `${key} applied ${new Date().toLocaleTimeString()}`;
      toast(`${key === 'enabled' ? 'Sentinel protections' : key.replace(/[A-Z]/g, m => ` ${m.toLowerCase()}`)} ${desired ? 'enabled' : 'disabled'} and saved.`);
      refreshLogs();
    } catch (error) {
      control.checked = !desired;
      toast(`Could not apply setting: ${error.message}`, true);
    } finally { control.disabled = false; }
  });
}

async function runServerAction(action) {
  if (!selectedGuild) return toast('Select a server first.', true);
  const labels = { backup: 'Create a structural backup', lock: 'LOCK all ordinary text channels', unlock: 'restore recorded channel permissions' };
  if (!window.confirm(`Sentinel will ${labels[action] || action} for ${guildData?.guild?.name || 'this server'}. Continue?`)) return;
  try {
    const result = await api(`/api/guilds/${selectedGuild}/actions`, { method: 'POST', body: JSON.stringify({ action }) });
    toast(result.message || 'Action completed.');
    await loadGuild(selectedGuild, document.querySelector(`.guild-item[data-id="${selectedGuild}"]`));
    await refreshLogs();
  } catch (error) { toast(error.message, true); }
}
document.querySelectorAll('[data-server-action]').forEach(button => button.addEventListener('click', () => runServerAction(button.dataset.serverAction)));

form.addEventListener('submit', async event => {
  event.preventDefault(); if (!selectedGuild) return;
  const body = {};
  for (const key of ['enabled','antiSpam','antiRaid','antiInvite','antiMassMention','antiNuke','antiLinks','antiCaps','antiDuplicate','antiWebhook','antiBotAdd','antiAccountAge','antiDangerousPerms','antiMassBan','antiRoleDelete','antiChannelDelete','antiGuildUpdate','autoResponse','autoBackupEnabled']) body[key] = form.elements[key].checked;
  body.securityProfile = form.elements.securityProfile.value;
  for (const key of ['joinThreshold','joinWindowSeconds','spamMessages','spamWindowSeconds','mentionLimit','minAccountAgeHours','autoBackupIntervalHours','backupRetention']) body[key] = Number(form.elements[key].value);
  body.punishment = form.elements.punishment.value; body.logChannelId = form.elements.logChannelId.value;
  const button = $('#save-button'); button.disabled = true; button.textContent = 'Saving…'; $('#save-status').textContent = '';
  try { await api(`/api/guilds/${selectedGuild}/settings`, { method: 'PATCH', body: JSON.stringify(body) }); $('#save-status').textContent = 'Saved just now'; toast('Server configuration saved.'); await loadGuild(selectedGuild, document.querySelector(`.guild-item[data-id="${selectedGuild}"]`)); }
  catch (e) { $('#save-status').textContent = e.message; toast(e.message, true); }
  finally { button.disabled = false; button.innerHTML = 'Save configuration <span>→</span>'; }
});
$('#refresh-logs')?.addEventListener('click', refreshLogs);
if (!window.__sentinelLogTimer) window.__sentinelLogTimer = setInterval(() => { if (isAdminPage && selectedGuild && !document.hidden) refreshLogs(); }, 15000);
$('#log-severity')?.addEventListener('change', refreshLogs);
let logSearchDebounce;
$('#log-search')?.addEventListener('input', () => { clearTimeout(logSearchDebounce); logSearchDebounce = setTimeout(refreshLogs, 300); });
$('#logout').addEventListener('click', async () => { sessionStorage.removeItem('sentinel.dashboardToken'); dashboardToken = ''; location.href = 'https://iik27.com/'; });
init();
