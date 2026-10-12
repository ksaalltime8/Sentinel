const { EmbedBuilder, PermissionsBitField } = require('discord.js');
const { Settings, SecurityEvent } = require('./models');

const joinBuckets = new Map();
const messageBuckets = new Map();
const deleteBuckets = new Map();

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

function isExempt(member) {
  return !member || member.user?.bot || member.permissions?.has(PermissionsBitField.Flags.Administrator);
}

function registerSecurityHandlers(client) {
  client.on('guildMemberAdd', async member => {
    try {
      const settings = await getSettings(member.guild);
      if (!settings.enabled || !settings.antiRaid) return;
      const now = Date.now();
      const arr = (joinBuckets.get(member.guild.id) || []).filter(t => now - t < settings.joinWindowSeconds * 1000);
      arr.push(now); joinBuckets.set(member.guild.id, arr);
      if (arr.length === settings.joinThreshold) {
        await logEvent(client, member.guild.id, 'Raid signal', `${arr.length} members joined within ${settings.joinWindowSeconds}s. Review recent joins and adjust verification settings.`, { severity: 'critical' });
      }
    } catch (e) { console.error('[anti-raid]', e.message); }
  });

  client.on('messageCreate', async message => {
    try {
      if (!message.guild || message.author.bot || !message.member) return;
      const settings = await getSettings(message.guild);
      if (!settings.enabled || isExempt(message.member)) return;
      const key = `${message.guild.id}:${message.author.id}`;
      const now = Date.now();
      const bucket = (messageBuckets.get(key) || []).filter(x => now - x.time < settings.spamWindowSeconds * 1000);
      bucket.push({ time: now, messageId: message.id }); messageBuckets.set(key, bucket);

      let reason = '';
      if (settings.antiSpam && bucket.length >= settings.spamMessages) reason = `Message spam (${bucket.length} messages in ${settings.spamWindowSeconds}s)`;
      if (!reason && settings.antiInvite && /(discord\.gg\/|discord(?:app)?\.com\/invite\/)/i.test(message.content)) reason = 'Discord invite link detected';
      if (!reason && settings.antiMassMention && (message.mentions.users.size + message.mentions.roles.size) >= settings.mentionLimit) reason = 'Mass mention detected';
      if (!reason) return;

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

  client.on('guildCreate', async guild => {
    await getSettings(guild).catch(() => {});
    await logEvent(client, guild.id, 'Sentinel joined', 'Sentinel is online. Configure logging and protection settings with /sentinel-config.', { severity: 'info' });
  });
  client.on('guildDelete', guild => { joinBuckets.delete(guild.id); });
}

module.exports = { getSettings, logEvent, registerSecurityHandlers };
