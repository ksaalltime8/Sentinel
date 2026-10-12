const { EmbedBuilder, PermissionsBitField, ChannelType } = require('discord.js');
const { Settings, SecurityEvent, Backup, saveSettings } = require('./models');

const joinBuckets = new Map();
const messageBuckets = new Map();
const deleteBuckets = new Map();
const duplicateBuckets = new Map();
const auditBuckets = new Map();

async function getSettings(guild) {
  return Settings.findOneAndUpdate(
    { guildId: guild.id },
    { $setOnInsert: { guildName: guild.name } },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
}

async function logEvent(client, guildId, type, message, options = {}) {
  try {
    const severity = options.severity || 'info';
    await SecurityEvent.create({ guildId, type, message: String(message).slice(0, 1000), actorId: options.actorId || '', targetId: options.targetId || '', severity });
    const guild = client.guilds.cache.get(guildId);
    if (!guild) return;
    const settings = await Settings.findOne({ guildId });
    const channelId = settings?.logChannelId || settings?.alertChannelId;
    if (!channelId) return;
    const channel = guild.channels.cache.get(channelId);
    if (!channel?.isTextBased() || !channel.permissionsFor(guild.members.me)?.has(PermissionsBitField.Flags.SendMessages)) return;
    const color = severity === 'critical' ? 0xe53935 : severity === 'warning' ? 0xffa000 : 0x5965f2;
    const embed = new EmbedBuilder().setColor(color).setTitle(`Sentinel • ${type}`).setDescription(String(message).slice(0, 3900)).setTimestamp();
    await channel.send({ embeds: [embed], allowedMentions: { parse: [] } }).catch(() => {});
  } catch (error) { console.error('[security-log]', error.message); }
}


async function createStructuralBackup(guild, createdBy = 'sentinel-auto') {
  await guild.roles.fetch();
  await guild.channels.fetch();
  const roles = guild.roles.cache.filter(r => r.id !== guild.id && !r.managed).map(r => ({ id: r.id, name: r.name, color: r.color, hoist: r.hoist, mentionable: r.mentionable, permissions: r.permissions.bitfield.toString(), position: r.position, unicodeEmoji: r.unicodeEmoji || null }));
  const channels = guild.channels.cache.map(c => ({
    id: c.id, name: c.name, type: c.type, parentId: c.parentId || null, position: c.position,
    topic: 'topic' in c ? c.topic : null, nsfw: 'nsfw' in c ? c.nsfw : false,
    rateLimitPerUser: 'rateLimitPerUser' in c ? c.rateLimitPerUser : 0,
    bitrate: 'bitrate' in c ? c.bitrate : null, userLimit: 'userLimit' in c ? c.userLimit : null,
    rtcRegion: 'rtcRegion' in c ? c.rtcRegion : null,
    permissionOverwrites: c.permissionOverwrites?.cache?.map(o => ({ id: o.id, type: o.type, allow: o.allow.bitfield.toString(), deny: o.deny.bitfield.toString() })) || []
  }));
  const settings = await getSettings(guild);
  return Backup.create({ guildId: guild.id, createdBy, data: { schemaVersion: 3, guildName: guild.name, roles, channels, settings: settings.toObject() } });
}

async function runScheduledBackups(client) {
  const dueSettings = await Settings.find({ autoBackupEnabled: true, enabled: true }).limit(200).catch(() => []);
  for (const settings of dueSettings) {
    const dueAt = settings.lastAutoBackupAt ? new Date(settings.lastAutoBackupAt).getTime() + settings.autoBackupIntervalHours * 3600000 : 0;
    if (Date.now() < dueAt) continue;
    const guild = client.guilds.cache.get(settings.guildId);
    if (!guild) continue;
    try {
      const backup = await createStructuralBackup(guild, 'sentinel-auto');
      settings.lastAutoBackupAt = new Date();
      await saveSettings(settings);
      const old = await Backup.find({ guildId: guild.id }).sort({ createdAt: -1 }).skip(settings.backupRetention).select('_id').lean();
      if (old.length) await Backup.deleteMany({ _id: { $in: old.map(x => x._id) }, guildId: guild.id });
      await logEvent(client, guild.id, 'Scheduled backup completed', `Automatic structural backup ${backup.id} created. Retention policy: ${settings.backupRetention} backups.`, { severity: 'info' });
    } catch (error) {
      await logEvent(client, guild.id, 'Scheduled backup failed', `Automatic backup failed: ${error.message}`, { severity: 'warning' });
    }
  }
}

function isExempt(member) {
  return !member || member.user?.bot || member.permissions?.has(PermissionsBitField.Flags.Administrator);
}

function registerSecurityHandlers(client) {
  client.on('guildMemberAdd', async member => {
    try {
      const settings = await getSettings(member.guild);
      if (!settings.enabled) return;
      const now = Date.now();
      const arr = (joinBuckets.get(member.guild.id) || []).filter(t => now - t < settings.joinWindowSeconds * 1000);
      arr.push(now); joinBuckets.set(member.guild.id, arr);

      if (settings.antiAccountAge && !member.user.bot && (now - member.user.createdTimestamp) < settings.minAccountAgeHours * 3600000) {
        const ageHours = Math.max(0, Math.floor((now - member.user.createdTimestamp) / 3600000));
        await logEvent(client, member.guild.id, 'New-account risk', `${member.user.tag} joined with an account approximately ${ageHours}h old; configured minimum is ${settings.minAccountAgeHours}h.`, { severity: 'warning', actorId: member.id, targetId: member.id });
        if (settings.autoResponse && settings.securityProfile === 'high' && !member.user.bot && member.kickable) {
          await member.kick('Sentinel high-security policy: account younger than configured minimum age').catch(() => {});
          await logEvent(client, member.guild.id, 'New-account containment', `Removed ${member.user.tag} under the configured high-security account-age policy.`, { severity: 'critical', actorId: member.id, targetId: member.id });
        }
      }

      if (member.user.bot && settings.antiBotAdd) {
        const audit = await member.guild.fetchAuditLogs({ type: 28, limit: 5 }).catch(() => null); // BOT_ADD
        const entry = audit?.entries.find(e => e.target?.id === member.id && Date.now() - e.createdTimestamp < 15000);
        const executorId = entry?.executorId;
        const trusted = Boolean(executorId && (executorId === member.guild.ownerId || executorId === client.user.id || settings.trustedUserIds?.includes(executorId)));
        if (!trusted) {
          await logEvent(client, member.guild.id, 'Untrusted bot added', `Bot ${member.user.tag} was added by ${executorId ? `<@${executorId}>` : 'an unknown inviter (audit entry unavailable)'}.`, { severity: 'critical', actorId: executorId || '', targetId: member.id });
          if (executorId && settings.autoResponse && settings.securityProfile === 'high' && member.kickable) {
            await member.kick('Sentinel high-security policy: bot added by a non-trusted inviter').catch(() => {});
            await logEvent(client, member.guild.id, 'Bot-add containment', `Attempted to remove ${member.user.tag}; review audit logs and trusted users.`, { severity: 'critical', actorId: executorId, targetId: member.id });
          }
        }
      }

      if (settings.antiRaid && arr.length >= settings.joinThreshold && arr.length <= settings.joinThreshold + 1) {
        await logEvent(client, member.guild.id, 'Raid signal', `${arr.length} members joined within ${settings.joinWindowSeconds}s. Review recent joins and verification settings.`, { severity: 'critical' });
        if (settings.autoResponse && settings.securityProfile === 'high' && !settings.lockdownActive) {
          const snapshot = []; let locked = 0;
          for (const channel of member.guild.channels.cache.values()) {
            if (![ChannelType.GuildText, ChannelType.GuildAnnouncement].includes(channel.type)) continue;
            try {
              const current = channel.permissionOverwrites.cache.get(member.guild.id);
              snapshot.push({ channelId: channel.id, sendMessages: current?.deny.has(PermissionsBitField.Flags.SendMessages) ? false : current?.allow.has(PermissionsBitField.Flags.SendMessages) ? true : null });
              await channel.permissionOverwrites.edit(member.guild.roles.everyone, { SendMessages: false }, { reason: 'Sentinel high-security raid response' }); locked++;
            } catch { /* count partial containment */ }
          }
          settings.lockdownSnapshot = snapshot; settings.lockdownActive = true; await saveSettings(settings);
          await logEvent(client, member.guild.id, 'Automatic raid containment', `High-security raid threshold reached. Locked ${locked} text channels. Server owner can restore recorded settings with /sentinel panic action:unlock confirm:true.`, { severity: 'critical' });
        }
      }
    } catch (e) { console.error('[anti-raid/member-join]', e.message); }
  });

  client.on('messageCreate', async message => {
    try {
      if (!message.guild || message.author.bot || !message.member) return;
      const settings = await getSettings(message.guild);
      if (!settings.enabled || isExempt(message.member) || settings.trustedUserIds?.includes(message.author.id)) return;
      const key = `${message.guild.id}:${message.author.id}`;
      const now = Date.now();
      const bucket = (messageBuckets.get(key) || []).filter(x => now - x.time < settings.spamWindowSeconds * 1000);
      bucket.push({ time: now, messageId: message.id }); messageBuckets.set(key, bucket);

      let reason = '';
      const duplicateKey = `${message.guild.id}:${message.author.id}`;
      const duplicates = (duplicateBuckets.get(duplicateKey) || []).filter(x => now - x.time < 20_000);
      duplicates.push({ time: now, content: message.content.slice(0, 500).toLowerCase().trim() }); duplicateBuckets.set(duplicateKey, duplicates);
      if (settings.antiSpam && bucket.length >= settings.spamMessages) reason = `Message spam (${bucket.length} messages in ${settings.spamWindowSeconds}s)`;
      if (!reason && settings.antiInvite && /(discord\.gg\/|discord(?:app)?\.com\/invite\/)/i.test(message.content)) reason = 'Discord invite link detected';
      if (!reason && settings.antiLinks && /https?:\/\//i.test(message.content)) reason = 'External link detected';
      if (!reason && settings.antiMassMention && (message.mentions.users.size + message.mentions.roles.size + (message.mentions.everyone ? settings.mentionLimit : 0)) >= settings.mentionLimit) reason = 'Mass mention detected';
      if (!reason && settings.antiCaps && message.content.length >= 12 && (message.content.replace(/[^A-Z]/g, '').length / Math.max(1, message.content.replace(/[^a-zA-Z]/g, '').length)) > 0.78) reason = 'Excessive capital letters detected';
      if (!reason && settings.antiDuplicate && duplicates.length >= 3 && duplicates.slice(-3).every(x => x.content && x.content === duplicates[duplicates.length - 1].content)) reason = 'Repeated duplicate message detected';
      if (!reason) return;

      if (!settings.autoResponse) { await logEvent(client, message.guild.id, 'Defense alert', `${message.author.tag} (${message.author.id}): ${reason}`, { severity: 'warning', actorId: message.author.id }); return; }
      await message.delete().catch(() => {});
      if (settings.punishment === 'timeout' && message.member.moderatable) {
        await message.member.timeout(10 * 60 * 1000, `Sentinel: ${reason}`).catch(() => {});
      }
      await logEvent(client, message.guild.id, 'Automated defense', `${message.author.tag} (${message.author.id}): ${reason}`, { severity: 'warning', actorId: message.author.id });
    } catch (e) { console.error('[message-defense]', e.message); }
  });

  const watchDelete = eventType => async (item) => {
    try {
      const guild = item.guild;
      if (!guild) return;
      const settings = await getSettings(guild);
      if (!settings.enabled || !settings.antiNuke) return;
      if (eventType === 'channel deletion' && !settings.antiChannelDelete) return;
      if (eventType === 'role deletion' && !settings.antiRoleDelete) return;
      const now = Date.now();
      const key = `${guild.id}:${eventType}`;
      const arr = (deleteBuckets.get(key) || []).filter(t => now - t < 15_000);
      arr.push(now); deleteBuckets.set(key, arr);
      if (arr.length === 3) {
        await logEvent(client, guild.id, 'Destructive action alert', `${arr.length} ${eventType} events occurred within 15 seconds. Sentinel alerted moderators; review the audit log and revoke suspicious permissions.`, { severity: 'critical' });
      }
    } catch (e) { console.error('[anti-nuke]', e.message); }
  };
  client.on('channelDelete', watchDelete('channel deletion'));
  client.on('roleDelete', watchDelete('role deletion'));


  client.on('guildAuditLogEntryCreate', async (entry, guild) => {
    try {
      const settings = await getSettings(guild);
      if (!settings.enabled || !settings.antiNuke) return;
      const riskyActions = new Set([
        10,  // CHANNEL_CREATE
        12,  // CHANNEL_DELETE
        22,  // MEMBER_BAN_ADD
        25,  // MEMBER_ROLE_UPDATE
        30,  // ROLE_CREATE
        31,  // ROLE_UPDATE
        32,  // ROLE_DELETE
        50,  // WEBHOOK_CREATE
        51,  // WEBHOOK_UPDATE
        52,  // WEBHOOK_DELETE
        28,  // BOT_ADD
        1,   // GUILD_UPDATE
        11,  // CHANNEL_UPDATE
        31,  // ROLE_UPDATE
        25   // MEMBER_ROLE_UPDATE
      ]);
      if (!riskyActions.has(entry.action)) return;
      if (entry.action === 12 && !settings.antiChannelDelete) return;
      if ([30, 31, 32].includes(entry.action) && entry.action === 32 && !settings.antiRoleDelete) return;
      if ([50, 51, 52].includes(entry.action) && !settings.antiWebhook) return;
      if (entry.action === 28 && !settings.antiBotAdd) return;
      if (entry.action === 1 && !settings.antiGuildUpdate) return;
      if (entry.action === 22 && !settings.antiMassBan) return;
      const executorId = entry.executorId;
      if (!executorId || executorId === client.user.id || executorId === guild.ownerId || settings.trustedUserIds?.includes(executorId)) return;
      const dangerousBits = PermissionsBitField.Flags.Administrator | PermissionsBitField.Flags.ManageGuild | PermissionsBitField.Flags.ManageRoles | PermissionsBitField.Flags.ManageChannels | PermissionsBitField.Flags.ManageWebhooks | PermissionsBitField.Flags.BanMembers | PermissionsBitField.Flags.KickMembers;
      if (settings.antiDangerousPerms && [30, 31].includes(entry.action)) {
        const targetRole = guild.roles.cache.get(entry.targetId);
        if (targetRole && (targetRole.permissions.bitfield & dangerousBits) !== 0n) {
          await logEvent(client, guild.id, 'Dangerous role permission change', `Role **${targetRole.name}** has powerful permissions and was created/updated by <@${executorId}>.`, { severity: 'critical', actorId: executorId, targetId: targetRole.id });
          if (settings.autoResponse && settings.securityProfile === 'high' && targetRole.editable && !targetRole.managed) {
            await targetRole.setPermissions(0n, 'Sentinel high-security containment: suspicious dangerous role permissions').catch(() => {});
            await logEvent(client, guild.id, 'Dangerous permission containment attempted', `Attempted to remove permissions from role **${targetRole.name}**. Verify manually; role hierarchy may prevent changes.`, { severity: 'critical', actorId: executorId, targetId: targetRole.id });
          }
        }
      }
      const key = `${guild.id}:${executorId}`;
      const now = Date.now();
      const rows = (auditBuckets.get(key) || []).filter(t => now - t < 20_000);
      rows.push(now); auditBuckets.set(key, rows);
      if (entry.action === 22) {
        const banKey = `${guild.id}:${executorId}:mass-ban`;
        const banRows = (auditBuckets.get(banKey) || []).filter(t => now - t < 20_000);
        banRows.push(now); auditBuckets.set(banKey, banRows);
        if (banRows.length === settings.massBanThreshold) await logEvent(client, guild.id, 'Possible mass-ban attack', `${banRows.length} member-ban audit events were attributed to <@${executorId}> in 20 seconds. Verify the audit log immediately.`, { severity: 'critical', actorId: executorId, targetId: entry.targetId || '' });
      }
      const webhookAction = [50, 51, 52].includes(entry.action);
      if (webhookAction && settings.antiWebhook) {
        await logEvent(client, guild.id, 'Webhook security event', `Audit log action ${entry.action} by <@${executorId}>. Review the webhook and revoke it if unauthorized.`, { severity: 'critical', actorId: executorId, targetId: entry.targetId || '' });
      }
      if (rows.length >= (settings.securityProfile === 'high' ? 2 : settings.securityProfile === 'medium' ? 3 : 5)) {
        await logEvent(client, guild.id, 'Possible anti-nuke incident', `${rows.length} risky administrative actions in 20 seconds by <@${executorId}> (latest audit action ${entry.action}).`, { severity: 'critical', actorId: executorId, targetId: entry.targetId || '' });
        if (settings.autoResponse && settings.securityProfile === 'high') {
          const member = await guild.members.fetch(executorId).catch(() => null);
          if (member && member.moderatable && executorId !== guild.ownerId && !member.user.bot) {
            await member.timeout(10 * 60 * 1000, 'Sentinel high-security automatic response: repeated risky audit-log actions').catch(() => {});
            await logEvent(client, guild.id, 'Automatic containment attempted', `Attempted a 10-minute timeout for <@${executorId}> after repeated risky audit actions. Verify the action in the audit log.`, { severity: 'critical', actorId: executorId });
          }
        }
        auditBuckets.set(key, []);
      }
    } catch (e) { console.error('[audit-defense]', e.message); }
  });

  client.on('guildCreate', async guild => {
    await getSettings(guild).catch(() => {});
    await logEvent(client, guild.id, 'Sentinel joined', 'Sentinel is online. Configure logging and protection settings with /sentinel config.', { severity: 'info' });
  });
  const backupTimer = setInterval(() => runScheduledBackups(client).catch(e => console.error('[scheduled-backup]', e.message)), 5 * 60 * 1000);
  backupTimer.unref?.();
  client.on('guildDelete', guild => { joinBuckets.delete(guild.id); for (const key of messageBuckets.keys()) if (key.startsWith(`${guild.id}:`)) messageBuckets.delete(key); for (const key of duplicateBuckets.keys()) if (key.startsWith(`${guild.id}:`)) duplicateBuckets.delete(key); for (const key of auditBuckets.keys()) if (key.startsWith(`${guild.id}:`)) auditBuckets.delete(key); });
}

module.exports = { getSettings, logEvent, registerSecurityHandlers, createStructuralBackup };
