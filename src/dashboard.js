const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const { Settings, SecurityEvent, Backup } = require('./models');
const { PermissionsBitField } = require('discord.js');

function createDashboard(client) {
  const app = express();
  const baseUrl = (process.env.DASHBOARD_URL || 'https://iik27.com').replace(/\/$/, '');
  const backendUrl = (process.env.BACKEND_URL || 'https://bot.k7devs.com').replace(/\/$/, '');
  const callbackUrl = `${backendUrl}/auth/callback`;
  const allowedOrigin = baseUrl;
  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", 'https://cdn.discordapp.com', 'https://*.discordapp.com', 'data:'], connectSrc: ["'self'", 'https://discord.com', 'https://discordapp.com'], objectSrc: ["'none'"], upgradeInsecureRequests: [] } } }));
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin === allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    }
    if (req.method === 'OPTIONS') return origin === allowedOrigin ? res.sendStatus(204) : res.sendStatus(403);
    next();
  });
  app.use(express.json({ limit: '32kb' }));
  app.use(session({ name: 'sentinel.sid', secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', maxAge: 8 * 60 * 60 * 1000 } }));
  app.use('/api', rateLimit({ windowMs: 60_000, limit: 90, standardHeaders: 'draft-8', legacyHeaders: false }));
  app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html', maxAge: '1h' }));

  function requireAuth(req, res, next) { if (!req.session.user || !req.session.accessToken) return res.status(401).json({ error: 'Sign in with Discord first.' }); next(); }
  async function fetchDiscord(url, token) {
    const response = await fetch(url, { headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'SentinelSecurity/1.0' } });
    if (!response.ok) throw new Error(`Discord API returned ${response.status}`);
    return response.json();
  }
  async function accessibleGuild(req, guildId) {
    const guilds = await fetchDiscord('https://discord.com/api/v10/users/@me/guilds', req.session.accessToken);
    const g = guilds.find(x => x.id === guildId);
    if (!g) return null;
    const perms = BigInt(g.permissions || '0');
    if ((perms & PermissionsBitField.Flags.Administrator) === 0n && (perms & PermissionsBitField.Flags.ManageGuild) === 0n) return null;
    const botGuild = client.guilds.cache.get(guildId);
    if (!botGuild) return null;
    return { oauthGuild: g, botGuild };
  }

  app.get('/auth/login', (req, res) => {
    if (!baseUrl || !process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_CLIENT_SECRET) return res.status(503).send('Dashboard OAuth is not configured. Set DASHBOARD_URL, DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET.');
    const state = crypto.randomBytes(24).toString('hex'); req.session.oauthState = state;
    const params = new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, response_type: 'code', redirect_uri: callbackUrl, scope: 'identify guilds', state, prompt: 'none' });
    res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
  });
  app.get('/auth/callback', async (req, res) => {
    try {
      if (!req.query.code || !req.query.state || req.query.state !== req.session.oauthState) return res.status(400).send('Invalid OAuth state. Please sign in again.');
      delete req.session.oauthState;
      const form = new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, client_secret: process.env.DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code: String(req.query.code), redirect_uri: callbackUrl });
      const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form });
      if (!tokenResponse.ok) throw new Error('Discord token exchange failed');
      const token = await tokenResponse.json();
      const user = await fetchDiscord('https://discord.com/api/v10/users/@me', token.access_token);
      req.session.user = { id: user.id, username: user.username, global_name: user.global_name || user.username, avatar: user.avatar };
      req.session.accessToken = token.access_token;
      res.redirect(`${baseUrl}/`);
    } catch (e) { console.error('[oauth]', e.message); res.status(502).send('Discord sign-in failed. Check OAuth settings and callback URL.'); }
  });
  app.post('/auth/logout', (req, res) => req.session.destroy(() => { res.clearCookie('sentinel.sid', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax' }); res.json({ ok: true }); }));
  app.get('/api/me', (req, res) => res.json({ user: req.session.user || null, botReady: client.isReady(), guildCount: client.guilds.cache.size }));
  app.get('/api/guilds', requireAuth, async (req, res) => {
    try {
      const guilds = await fetchDiscord('https://discord.com/api/v10/users/@me/guilds', req.session.accessToken);
      const result = guilds.filter(g => {
        const p = BigInt(g.permissions || '0');
        return ((p & PermissionsBitField.Flags.Administrator) !== 0n || (p & PermissionsBitField.Flags.ManageGuild) !== 0n) && client.guilds.cache.has(g.id);
      }).map(g => ({ id: g.id, name: g.name, icon: g.icon, botPresent: true }));
      res.json({ guilds: result });
    } catch (e) { res.status(502).json({ error: 'Could not load Discord servers.' }); }
  });
  app.get('/api/guilds/:id', requireAuth, async (req, res) => {
    try {
      const access = await accessibleGuild(req, req.params.id); if (!access) return res.status(403).json({ error: 'You need Manage Server or Administrator permission, and Sentinel must be in that server.' });
      const settings = await Settings.findOneAndUpdate({ guildId: req.params.id }, { $setOnInsert: { guildName: access.botGuild.name } }, { upsert: true, new: true, setDefaultsOnInsert: true }).lean();
      const events = await SecurityEvent.find({ guildId: req.params.id }).sort({ createdAt: -1 }).limit(15).lean();
      const backups = await Backup.find({ guildId: req.params.id }).select('_id createdBy createdAt').sort({ createdAt: -1 }).limit(10).lean();
      const channels = access.botGuild.channels.cache.filter(c => c.isTextBased() && c.guildId === req.params.id).map(c => ({ id: c.id, name: c.name }));
      res.json({ settings, events, backups, channels, guild: { id: access.botGuild.id, name: access.botGuild.name, memberCount: access.botGuild.memberCount } });
    } catch (e) { console.error('[dashboard guild]', e.message); res.status(500).json({ error: 'Could not load server data.' }); }
  });
  app.patch('/api/guilds/:id/settings', requireAuth, async (req, res) => {
    try {
      const access = await accessibleGuild(req, req.params.id); if (!access) return res.status(403).json({ error: 'Not authorized for this server.' });
      const allowed = ['enabled', 'logChannelId', 'antiSpam', 'antiRaid', 'antiInvite', 'antiMassMention', 'antiNuke', 'joinThreshold', 'joinWindowSeconds', 'spamMessages', 'spamWindowSeconds', 'mentionLimit', 'punishment'];
      const update = {};
      for (const key of allowed) if (Object.prototype.hasOwnProperty.call(req.body || {}, key)) update[key] = req.body[key];
      const bools = ['enabled', 'antiSpam', 'antiRaid', 'antiInvite', 'antiMassMention', 'antiNuke'];
      for (const key of bools) if (key in update && typeof update[key] !== 'boolean') return res.status(400).json({ error: `${key} must be true or false.` });
      const numeric = { joinThreshold: [3, 30], joinWindowSeconds: [5, 60], spamMessages: [3, 20], spamWindowSeconds: [3, 30], mentionLimit: [3, 20] };
      for (const [key, [min, max]] of Object.entries(numeric)) if (key in update && (!Number.isInteger(update[key]) || update[key] < min || update[key] > max)) return res.status(400).json({ error: `${key} must be an integer between ${min} and ${max}.` });
      if ('punishment' in update && !['delete', 'timeout'].includes(update.punishment)) return res.status(400).json({ error: 'Invalid punishment.' });
      if ('logChannelId' in update && update.logChannelId) {
        const channel = access.botGuild.channels.cache.get(update.logChannelId);
        if (!channel || !channel.isTextBased()) return res.status(400).json({ error: 'Choose a text channel in this server.' });
      }
      update.guildName = access.botGuild.name; update.updatedAt = new Date();
      const settings = await Settings.findOneAndUpdate({ guildId: req.params.id }, { $set: update, $setOnInsert: { guildId: req.params.id } }, { upsert: true, new: true, runValidators: true });
      await SecurityEvent.create({ guildId: req.params.id, type: 'Dashboard settings', message: `Settings updated through dashboard by ${req.session.user.username} (${req.session.user.id}).`, actorId: req.session.user.id, severity: 'info' });
      res.json({ ok: true, settings });
    } catch (e) { console.error('[dashboard save]', e.message); res.status(500).json({ error: 'Could not save settings.' }); }
  });
  app.get('/health', (req, res) => res.json({ ok: true, botReady: client.isReady(), uptimeSeconds: Math.floor(process.uptime()) }));
  app.use((err, req, res, next) => { console.error('[dashboard]', err.message); res.status(500).json({ error: 'Internal server error.' }); });
  return app;
}
module.exports = { createDashboard };
