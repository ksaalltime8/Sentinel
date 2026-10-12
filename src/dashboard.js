const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const { Settings, SecurityEvent, Backup, saveSettings } = require('./models');
const { PermissionsBitField, ChannelType } = require('discord.js');
const { createStructuralBackup } = require('./security');
const mongoose = require('mongoose');

function createDashboard(client) {
  const app = express();
  const baseUrl = (process.env.DASHBOARD_URL || 'https://iik27.com').replace(/\/$/, '');
  const backendUrl = (process.env.BACKEND_URL || 'https://bot.k7devs.com').replace(/\/$/, '');
  const callbackUrl = `${backendUrl}/auth/callback`;
  const allowedOrigins = new Set([baseUrl, backendUrl]);
  // Single-use OAuth handoff avoids third-party cookie restrictions across iik27.com and k7devs.com.
  const dashboardHandoffCodes = new Map();
  const dashboardAccessTokens = new Map();
  const signingSecret = process.env.SESSION_SECRET || '';
  // Discord's /users/@me/guilds endpoint is user-token rate limited. Cache successful
  // responses briefly and reuse a recent snapshot during 429s to prevent the dashboard
  // making one OAuth request for every panel, log and settings request.
  const oauthGuildCache = new Map();
  const oauthGuildInflight = new Map();
  const OAUTH_GUILD_CACHE_MS = 60_000;
  const OAUTH_GUILD_STALE_MS = 10 * 60_000;
  const tokenCacheKey = token => crypto.createHash('sha256').update(String(token)).digest('hex');
  function issueDashboardToken(user, accessToken) {
    const token = crypto.randomBytes(32).toString('hex');
    dashboardAccessTokens.set(token, { user, accessToken, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
    for (const [key, value] of dashboardAccessTokens) if (value.expiresAt < Date.now()) dashboardAccessTokens.delete(key);
    while (dashboardAccessTokens.size > 1000) dashboardAccessTokens.delete(dashboardAccessTokens.keys().next().value);
    return token;
  }
  function readDashboardToken(token) {
    if (typeof token !== 'string') return null;
    const entry = dashboardAccessTokens.get(token);
    if (!entry || entry.expiresAt < Date.now()) { dashboardAccessTokens.delete(token); return null; }
    return entry;
  }
  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'], imgSrc: ["'self'", 'https://cdn.discordapp.com', 'https://*.discordapp.com', 'data:'], connectSrc: ["'self'", 'https://iik27.com', 'https://bot.k7devs.com', 'https://discord.com', 'https://discordapp.com'], objectSrc: ["'none'"], upgradeInsecureRequests: [] } } }));
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && allowedOrigins.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    }
    if (req.method === 'OPTIONS') return origin && allowedOrigins.has(origin) ? res.sendStatus(204) : res.sendStatus(403);
    next();
  });
  app.use(express.json({ limit: '32kb' }));
  app.use(session({ name: 'sentinel.sid', secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false, proxy: true, cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', maxAge: 8 * 60 * 60 * 1000 } }));
  app.use((req, res, next) => {
    const header = req.headers.authorization || '';
    if (header.startsWith('Bearer ')) {
      const payload = readDashboardToken(header.slice(7));
      if (payload) { req.session.user = payload.user; req.session.accessToken = payload.accessToken; req.dashboardTokenAuth = true; }
    }
    next();
  });
  app.use('/api', rateLimit({ windowMs: 60_000, limit: 90, standardHeaders: 'draft-8', legacyHeaders: false }));
  // Keep a compatibility route on the backend, but the public dashboard lives on iik27.com/admin.
  app.get('/admin', (req, res) => res.redirect(302, `${baseUrl}/admin`));
  app.get('/admin/', (req, res) => res.redirect(302, `${baseUrl}/admin`));
  app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html', maxAge: '1h' }));

  function requireAuth(req, res, next) { if (!req.session.user || !req.session.accessToken) return res.status(401).json({ error: 'Sign in with Discord first.' }); next(); }
  async function fetchDiscord(url, token) {
    const response = await fetch(url, { headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'SentinelSecurity/1.0' } });
    if (!response.ok) {
      const error = new Error(`Discord API returned ${response.status} for ${new URL(url).pathname}`);
      error.discordStatus = response.status;
      const retryAfter = Number(response.headers.get('retry-after'));
      if (Number.isFinite(retryAfter) && retryAfter > 0) error.retryAfter = Math.ceil(retryAfter);
      throw error;
    }
    return response.json();
  }
  async function fetchOAuthGuilds(accessToken) {
    const key = tokenCacheKey(accessToken);
    const now = Date.now();
    const cached = oauthGuildCache.get(key);
    if (cached && cached.expiresAt > now) return cached.guilds;
    if (oauthGuildInflight.has(key)) return oauthGuildInflight.get(key);
    const request = (async () => {
      try {
        const guilds = await fetchDiscord('https://discord.com/api/v10/users/@me/guilds', accessToken);
        oauthGuildCache.set(key, { guilds, expiresAt: Date.now() + OAUTH_GUILD_CACHE_MS, staleUntil: Date.now() + OAUTH_GUILD_STALE_MS });
        while (oauthGuildCache.size > 1000) oauthGuildCache.delete(oauthGuildCache.keys().next().value);
        return guilds;
      } catch (error) {
        const latest = oauthGuildCache.get(key);
        if (error.discordStatus === 429 && latest && latest.staleUntil > Date.now()) {
          console.warn('[dashboard guild cache] Reusing recent Discord guild list after HTTP 429.');
          return latest.guilds;
        }
        throw error;
      } finally {
        oauthGuildInflight.delete(key);
      }
    })();
    oauthGuildInflight.set(key, request);
    return request;
  }
  function applyDiscordError(res, error) {
    if (error?.discordStatus === 401) return res.status(401).json({ error: 'Your Discord login expired. Sign out and sign in again.' });
    if (error?.discordStatus === 403) return res.status(403).json({ error: 'Discord did not allow this request. Sign in again and approve the requested permissions.' });
    if (error?.discordStatus === 429) {
      if (error.retryAfter) res.setHeader('Retry-After', String(error.retryAfter));
      return res.status(429).json({ error: 'Discord is temporarily rate-limiting server checks. Wait a moment and retry; Sentinel will reuse cached server access where possible.' });
    }
    return null;
  }
  function databaseReady() { return mongoose.connection.readyState === 1; }
  function reportGuildError(error, guildId) {
    console.error('[dashboard guild]', { guildId, message: error?.message, name: error?.name, mongoState: mongoose.connection.readyState, discordStatus: error?.discordStatus, stack: error?.stack });
  }
  async function accessibleGuild(req, guildId) {
    const guilds = await fetchOAuthGuilds(req.session.accessToken);
    const g = guilds.find(x => x.id === guildId);
    if (!g || g.owner !== true) return null; // Dashboard access is restricted to the actual Discord server owner.
    const botGuild = client.guilds.cache.get(guildId);
    if (!botGuild) return null;
    return { oauthGuild: g, botGuild };
  }

  app.get('/auth/login', (req, res) => {
    if (!baseUrl || !process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_CLIENT_SECRET) return res.status(503).send('Dashboard OAuth is not configured. Set DASHBOARD_URL, DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET.');
    const requestedReturn = typeof req.query.next === 'string' && req.query.next === '/admin' ? '/admin' : '/';
    const state = crypto.randomBytes(32).toString('hex');
    req.session.oauthState = state;
    req.session.returnTo = requestedReturn;
    // Keep OAuth state in a short-lived, backend-host cookie as well as the session.
    // Discord returns to this backend host, so SameSite=Lax works for the top-level callback.
    res.cookie('sentinel.oauth_state', state, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 10 * 60 * 1000,
      path: '/auth'
    });
    const params = new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, response_type: 'code', redirect_uri: callbackUrl, scope: 'identify guilds', state });
    req.session.save((err) => {
      if (err) {
        console.error('[oauth] Could not save login session:', err.message);
        return res.status(500).send('Could not start Discord sign-in. Please try again.');
      }
      res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
    });
  });
  app.get('/auth/callback', async (req, res) => {
    try {
      const queryState = typeof req.query.state === 'string' ? req.query.state : '';
      const sessionState = req.session.oauthState;
      // express.json does not parse cookies, so read the state cookie safely from the header.
      const rawCookie = req.headers.cookie || '';
      const stateCookiePair = rawCookie.split(';').map(v => v.trim()).find(v => v.startsWith('sentinel.oauth_state='));
      const parsedCookieState = stateCookiePair ? decodeURIComponent(stateCookiePair.slice('sentinel.oauth_state='.length)) : undefined;
      const safeEqual = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
      const stateValid = queryState && (safeEqual(queryState, sessionState) || safeEqual(queryState, parsedCookieState));
      res.clearCookie('sentinel.oauth_state', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/auth' });
      if (!req.query.code || !stateValid) return res.status(400).send('Invalid OAuth state. Your sign-in session was not preserved or has expired. Return to https://iik27.com and sign in again.');
      delete req.session.oauthState;
      const form = new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, client_secret: process.env.DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code: String(req.query.code), redirect_uri: callbackUrl });
      const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form });
      if (!tokenResponse.ok) throw new Error(`Discord token exchange failed (${tokenResponse.status})`);
      const token = await tokenResponse.json();
      const user = await fetchDiscord('https://discord.com/api/v10/users/@me', token.access_token);
      req.session.user = { id: user.id, username: user.username, global_name: user.global_name || user.username, avatar: user.avatar };
      req.session.accessToken = token.access_token;
      req.session.save((err) => {
        if (err) {
          console.error('[oauth] Could not save authenticated session:', err.message);
          return res.status(500).send('Sign-in succeeded, but the session could not be saved. Please try again.');
        }
        const returnTo = req.session.returnTo === '/admin' ? '/admin' : '/';
        delete req.session.returnTo;
        if (returnTo === '/admin') {
          const code = crypto.randomBytes(32).toString('hex');
          dashboardHandoffCodes.set(code, { user: req.session.user, accessToken: req.session.accessToken, expiresAt: Date.now() + 60_000 });
          for (const [key, value] of dashboardHandoffCodes) if (value.expiresAt < Date.now()) dashboardHandoffCodes.delete(key);
          while (dashboardHandoffCodes.size > 1000) dashboardHandoffCodes.delete(dashboardHandoffCodes.keys().next().value);
          return res.redirect(`${baseUrl}/admin?code=${encodeURIComponent(code)}`);
        }
        res.redirect(`${baseUrl}/`);
      });
    } catch (e) { console.error('[oauth]', e.message); res.status(502).send('Discord sign-in failed. Check OAuth settings and callback URL.'); }
  });
  app.post('/auth/exchange', (req, res) => {
    const code = typeof req.body?.code === 'string' ? req.body.code : '';
    const entry = dashboardHandoffCodes.get(code);
    dashboardHandoffCodes.delete(code);
    if (!entry || entry.expiresAt < Date.now()) return res.status(401).json({ error: 'Sign-in handoff expired. Please sign in again.' });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true, token: issueDashboardToken(entry.user, entry.accessToken), user: entry.user, expiresIn: 8 * 60 * 60 });
  });
  app.post('/auth/logout', (req, res) => req.session.destroy(() => { res.clearCookie('sentinel.sid', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' }); res.json({ ok: true }); }));
  app.get('/api/public-stats', async (req, res) => {
    // Public stats are intentionally cacheable and do not use cookies. Allow the public
    // iik27.com site even if Hostinger's DASHBOARD_URL contains a different alias.
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'public, max-age=15, stale-while-revalidate=30');
    try {
      const guilds = client.guilds.cache;
      const totalMembers = guilds.reduce((sum, guild) => sum + (Number(guild.memberCount) || 0), 0);
      let protectedServers = null;
      let eventsLast24h = null;
      if (databaseReady()) {
        const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
        // Do not hold the public landing page hostage to a slow MongoDB count.
        // Core server/member/online fields are already available from Discord cache.
        const counts = await Promise.race([
          Promise.all([
            Settings.countDocuments({ enabled: true }).maxTimeMS(1200),
            SecurityEvent.countDocuments({ createdAt: { $gte: since } }).maxTimeMS(1200)
          ]),
          new Promise(resolve => setTimeout(() => resolve([null, null]), 1400))
        ]);
        [protectedServers, eventsLast24h] = counts;
      }
      const payload = {
        botReady: client.isReady(),
        serverCount: guilds.size,
        memberCount: totalMembers,
        protectedServers,
        eventsLast24h,
        uptimeSeconds: Math.floor(process.uptime()),
        generatedAt: new Date().toISOString()
      };
      res.json(payload);
    } catch (error) {
      console.error('[public stats]', error.message);
      res.status(503).json({ error: 'Public statistics are temporarily unavailable.' });
    }
  });
  app.get('/api/public-config', (req, res) => {
    // Public configuration is safe to read without authentication or credentials.
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=300');
    const clientId = process.env.DISCORD_CLIENT_ID || '';
    const permissions = '109978006528'; // View channels, send/read messages, manage messages, moderate members.
    const inviteUrl = clientId ? `https://discord.com/oauth2/authorize?${new URLSearchParams({ client_id: clientId, permissions, scope: 'bot applications.commands' }).toString()}` : null;
    res.json({ dashboardUrl: baseUrl, inviteUrl, botReady: client.isReady() });
  });
  app.get('/api/me', (req, res) => res.json({ user: req.session.user || null, botReady: client.isReady(), guildCount: client.guilds.cache.size }));
  app.get('/api/guilds', requireAuth, async (req, res) => {
    try {
      const guilds = await fetchOAuthGuilds(req.session.accessToken);
      const result = guilds.filter(g => g.owner === true && client.guilds.cache.has(g.id))
        .map(g => ({ id: g.id, name: g.name, icon: g.icon, owner: true, botPresent: true }));
      res.json({ guilds: result });
    } catch (e) {
      console.error('[dashboard guild list]', { message: e.message, discordStatus: e.discordStatus, stack: e.stack });
      const discordResponse = applyDiscordError(res, e);
      if (discordResponse) return discordResponse;
      res.status(502).json({ error: 'Could not load Discord servers. Check the backend application logs.' });
    }
  });
  app.get('/api/guilds/:id', requireAuth, async (req, res) => {
    const guildId = String(req.params.id || '');
    try {
      const access = await accessibleGuild(req, guildId);
      if (!access) return res.status(403).json({ error: 'Only the actual Discord server owner can access this dashboard, and Sentinel must be installed in that server.' });
      if (!databaseReady()) return res.status(503).json({ error: 'Sentinel database is temporarily unavailable. Please retry shortly.' });
      const settings = await Settings.findOneAndUpdate(
        { guildId },
        { $setOnInsert: { guildId, guildName: access.botGuild.name } },
        { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true }
      ).lean();
      const [events, backups] = await Promise.all([
        SecurityEvent.find({ guildId }).sort({ createdAt: -1 }).limit(50).lean(),
        Backup.find({ guildId }).select('_id createdBy createdAt').sort({ createdAt: -1 }).limit(10).lean()
      ]);
      const channels = access.botGuild.channels.cache
        .filter(c => c.guildId === guildId && c.isTextBased() && typeof c.name === 'string')
        .map(c => ({ id: c.id, name: c.name }));
      return res.json({ settings, events, backups, channels, guild: { id: access.botGuild.id, name: access.botGuild.name, memberCount: access.botGuild.memberCount ?? null } });
    } catch (e) {
      reportGuildError(e, guildId);
      const discordResponse = applyDiscordError(res, e);
      if (discordResponse) return discordResponse;
      if (e.name === 'MongoServerSelectionError' || e.name === 'MongooseServerSelectionError' || !databaseReady()) return res.status(503).json({ error: 'Sentinel cannot reach MongoDB right now. Check the backend database connection.' });
      return res.status(500).json({ error: 'Could not load server data. Check the backend application logs for the [dashboard guild] error details.' });
    }
  });
  app.get('/api/guilds/:id/events', requireAuth, async (req, res) => {
    const guildId = String(req.params.id || '');
    try {
      const access = await accessibleGuild(req, guildId);
      if (!access) return res.status(403).json({ error: 'Only the actual Discord server owner can view this server’s logs.' });
      if (!databaseReady()) return res.status(503).json({ error: 'Sentinel database is temporarily unavailable.' });
      const limitRaw = Number.parseInt(String(req.query.limit || '50'), 10);
      const limit = Number.isInteger(limitRaw) ? Math.max(1, Math.min(100, limitRaw)) : 50;
      const filter = { guildId };
      if (['info', 'warning', 'critical'].includes(String(req.query.severity || ''))) filter.severity = String(req.query.severity);
      if (typeof req.query.q === 'string' && req.query.q.trim()) {
        const safe = req.query.q.trim().slice(0, 80).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        filter.$or = [{ type: { $regex: safe, $options: 'i' } }, { message: { $regex: safe, $options: 'i' } }, { actorId: { $regex: safe, $options: 'i' } }, { targetId: { $regex: safe, $options: 'i' } }];
      }
      const events = await SecurityEvent.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
      res.setHeader('Cache-Control', 'no-store');
      res.json({ events, count: events.length, limit });
    } catch (error) {
      reportGuildError(error, guildId);
      const discordResponse = applyDiscordError(res, error);
      if (discordResponse) return discordResponse;
      res.status(500).json({ error: 'Could not load security logs. Check the backend application logs.' });
    }
  });

  app.patch('/api/guilds/:id/settings', requireAuth, async (req, res) => {
    try {
      const access = await accessibleGuild(req, req.params.id); if (!access) return res.status(403).json({ error: 'Not authorized for this server.' });
      const allowed = ['enabled', 'logChannelId', 'securityProfile', 'antiSpam', 'antiRaid', 'antiInvite', 'antiMassMention', 'antiNuke', 'antiLinks', 'antiCaps', 'antiDuplicate', 'antiWebhook', 'antiBotAdd', 'antiAccountAge', 'antiDangerousPerms', 'antiMassBan', 'antiRoleDelete', 'antiChannelDelete', 'antiGuildUpdate', 'autoResponse', 'autoBackupEnabled', 'minAccountAgeHours', 'autoBackupIntervalHours', 'backupRetention', 'joinThreshold', 'joinWindowSeconds', 'spamMessages', 'spamWindowSeconds', 'mentionLimit', 'punishment'];
      const update = {};
      for (const key of allowed) if (Object.prototype.hasOwnProperty.call(req.body || {}, key)) update[key] = req.body[key];
      if (Object.prototype.hasOwnProperty.call(req.body || {}, 'securityProfile')) {
        const presets = {
          low: { antiSpam:true, antiRaid:true, antiInvite:true, antiMassMention:true, antiNuke:true, antiLinks:false, antiCaps:false, antiDuplicate:false, antiWebhook:true, antiBotAdd:true, antiAccountAge:false, antiDangerousPerms:true, antiMassBan:true, antiRoleDelete:true, antiChannelDelete:true, antiGuildUpdate:true, autoResponse:false, joinThreshold:12, spamMessages:8, mentionLimit:8, punishment:'delete' },
          medium: { antiSpam:true, antiRaid:true, antiInvite:true, antiMassMention:true, antiNuke:true, antiLinks:false, antiCaps:true, antiDuplicate:true, antiWebhook:true, antiBotAdd:true, antiAccountAge:false, antiDangerousPerms:true, antiMassBan:true, antiRoleDelete:true, antiChannelDelete:true, antiGuildUpdate:true, autoResponse:true, joinThreshold:8, spamMessages:6, mentionLimit:5, punishment:'timeout' },
          high: { antiSpam:true, antiRaid:true, antiInvite:true, antiMassMention:true, antiNuke:true, antiLinks:true, antiCaps:true, antiDuplicate:true, antiWebhook:true, antiBotAdd:true, antiAccountAge:true, antiDangerousPerms:true, antiMassBan:true, antiRoleDelete:true, antiChannelDelete:true, antiGuildUpdate:true, autoResponse:true, minAccountAgeHours:24, joinThreshold:5, spamMessages:4, mentionLimit:3, punishment:'timeout' }
        };
        for (const [key, value] of Object.entries(presets[update.securityProfile] || {})) if (!Object.prototype.hasOwnProperty.call(req.body || {}, key)) update[key] = value;
      }
      const bools = ['enabled', 'antiSpam', 'antiRaid', 'antiInvite', 'antiMassMention', 'antiNuke', 'antiLinks', 'antiCaps', 'antiDuplicate', 'antiWebhook', 'antiBotAdd', 'antiAccountAge', 'antiDangerousPerms', 'antiMassBan', 'antiRoleDelete', 'antiChannelDelete', 'antiGuildUpdate', 'autoResponse', 'autoBackupEnabled'];
      for (const key of bools) if (key in update && typeof update[key] !== 'boolean') return res.status(400).json({ error: `${key} must be true or false.` });
      const numeric = { joinThreshold: [3, 30], joinWindowSeconds: [5, 60], spamMessages: [3, 20], spamWindowSeconds: [3, 30], mentionLimit: [3, 20], minAccountAgeHours: [1, 8760], autoBackupIntervalHours: [1, 168], backupRetention: [1, 100] };
      for (const [key, [min, max]] of Object.entries(numeric)) if (key in update && (!Number.isInteger(update[key]) || update[key] < min || update[key] > max)) return res.status(400).json({ error: `${key} must be an integer between ${min} and ${max}.` });
      if ('securityProfile' in update && !['low', 'medium', 'high'].includes(update.securityProfile)) return res.status(400).json({ error: 'securityProfile must be low, medium, or high.' });
      if ('punishment' in update && !['delete', 'timeout'].includes(update.punishment)) return res.status(400).json({ error: 'Invalid punishment.' });
      if ('logChannelId' in update && update.logChannelId) {
        const channel = access.botGuild.channels.cache.get(update.logChannelId);
        if (!channel || !channel.isTextBased()) return res.status(400).json({ error: 'Choose a text channel in this server.' });
      }
      update.guildName = access.botGuild.name; update.updatedAt = new Date();
      const settings = await Settings.findOneAndUpdate({ guildId: req.params.id }, { $set: update, $setOnInsert: { guildId: req.params.id } }, { upsert: true, new: true, runValidators: true });
      await SecurityEvent.create({ guildId: req.params.id, type: 'Dashboard settings', message: `Settings updated through dashboard by ${req.session.user.username} (${req.session.user.id}).`, actorId: req.session.user.id, severity: 'info' });
      res.json({ ok: true, settings });
    } catch (e) { console.error('[dashboard save]', e.message); const discordResponse = applyDiscordError(res, e); if (discordResponse) return discordResponse; res.status(500).json({ error: 'Could not save settings.' }); }
  });
  app.post('/api/guilds/:id/actions', requireAuth, async (req, res) => {
    const guildId = String(req.params.id || '');
    const action = String(req.body?.action || '');
    try {
      const access = await accessibleGuild(req, guildId);
      if (!access) return res.status(403).json({ error: 'Only the actual Discord server owner can run server actions.' });
      if (!databaseReady()) return res.status(503).json({ error: 'Sentinel database is temporarily unavailable.' });
      const guild = access.botGuild;
      const settings = await Settings.findOneAndUpdate(
        { guildId }, { $setOnInsert: { guildId, guildName: guild.name } },
        { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true }
      );
      const me = guild.members.me || await guild.members.fetchMe().catch(() => null);
      if (action === 'backup') {
        const backup = await createStructuralBackup(guild, req.session.user.id);
        await SecurityEvent.create({ guildId, type: 'Dashboard backup created', message: `Structural backup ${backup._id} created from the owner dashboard by ${req.session.user.username} (${req.session.user.id}).`, actorId: req.session.user.id, severity: 'info' });
        return res.json({ ok: true, action, backup: { _id: String(backup._id), createdAt: backup.createdAt }, message: 'Structural backup created.' });
      }
      if (action === 'lock' || action === 'unlock') {
        if (!me?.permissions.has(PermissionsBitField.Flags.ManageChannels)) return res.status(403).json({ error: 'Sentinel needs Manage Channels to lock or unlock the server.' });
        const channels = await guild.channels.fetch();
        let changed = 0, failed = 0;
        if (action === 'lock') {
          if (settings.lockdownActive) return res.status(409).json({ error: 'A Sentinel lockdown is already active. Use Unlock to restore its recorded settings.' });
          const snapshot = [];
          for (const channel of channels.values()) {
            if (!channel || ![ChannelType.GuildText, ChannelType.GuildAnnouncement].includes(channel.type) || channel.isThread?.()) continue;
            try {
              const current = channel.permissionOverwrites.cache.get(guild.id);
              snapshot.push({ channelId: channel.id, sendMessages: current?.deny.has(PermissionsBitField.Flags.SendMessages) ? false : current?.allow.has(PermissionsBitField.Flags.SendMessages) ? true : null });
              await channel.permissionOverwrites.edit(guild.roles.everyone, { SendMessages: false }, { reason: `Sentinel dashboard emergency lockdown by ${req.session.user.username}` });
              changed++;
            } catch { failed++; }
          }
          settings.lockdownSnapshot = snapshot; settings.lockdownActive = true; await saveSettings(settings);
        } else {
          if (!settings.lockdownActive || !Array.isArray(settings.lockdownSnapshot) || !settings.lockdownSnapshot.length) return res.status(409).json({ error: 'No saved Sentinel lockdown snapshot exists. Sentinel will not blindly remove existing channel restrictions.' });
          for (const row of settings.lockdownSnapshot) {
            const channel = channels.get(row.channelId); if (!channel) continue;
            try {
              await channel.permissionOverwrites.edit(guild.roles.everyone, { SendMessages: row.sendMessages === false ? false : row.sendMessages === true ? true : null }, { reason: `Sentinel dashboard emergency unlock by ${req.session.user.username}` });
              changed++;
            } catch { failed++; }
          }
          settings.lockdownActive = false; settings.lockdownSnapshot = []; await saveSettings(settings);
        }
        await SecurityEvent.create({ guildId, type: `Dashboard emergency ${action}`, message: `${req.session.user.username} ran ${action}. Changed ${changed} channels; ${failed} failed.`, actorId: req.session.user.id, severity: 'critical' });
        return res.json({ ok: true, action, changed, failed, lockdownActive: settings.lockdownActive, message: `${action === 'lock' ? 'Lockdown' : 'Unlock'} finished. Changed ${changed} channels; ${failed} failed.` });
      }
      return res.status(400).json({ error: 'Unknown action. Supported actions: backup, lock, unlock.' });
    } catch (error) {
      reportGuildError(error, guildId);
      const discordResponse = applyDiscordError(res, error);
      if (discordResponse) return discordResponse;
      return res.status(500).json({ error: `Action failed: ${error.message || 'unexpected backend error'}` });
    }
  });

  app.get('/health', (req, res) => res.json({ ok: true, botReady: client.isReady(), uptimeSeconds: Math.floor(process.uptime()) }));
  app.use((err, req, res, next) => { console.error('[dashboard]', err.message); res.status(500).json({ error: 'Internal server error.' }); });
  return app;
}
module.exports = { createDashboard };
