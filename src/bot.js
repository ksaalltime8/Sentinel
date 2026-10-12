const {
  Client, GatewayIntentBits, Partials, REST, Routes, SlashCommandBuilder,
  PermissionFlagsBits, EmbedBuilder, ChannelType, MessageFlags, ActivityType
} = require('discord.js');
const { Settings, SecurityEvent, Backup, saveSettings } = require('./models');
const { getSettings, logEvent, registerSecurityHandlers, createStructuralBackup } = require('./security');

const commands = [
  new SlashCommandBuilder().setName('sentinel').setDescription('Sentinel security tools')
    .addSubcommand(s => s.setName('status').setDescription('Show Sentinel status and enabled defenses'))
    .addSubcommand(s => s.setName('security').setDescription('Set this server security profile')
      .addStringOption(o => o.setName('profile').setDescription('Choose the security intensity').setRequired(true).addChoices({name:'Low — alerts and basic filters',value:'low'},{name:'Medium — balanced automatic defense',value:'medium'},{name:'High — aggressive incident response',value:'high'})))
    .addSubcommand(s => s.setName('features').setDescription('Enable or disable an individual security defense')
      .addStringOption(o => o.setName('feature').setDescription('Defense to configure').setRequired(true).addChoices(
        {name:'Anti-spam',value:'antiSpam'},{name:'Anti-raid',value:'antiRaid'},{name:'Anti-invite links',value:'antiInvite'},{name:'Anti-external links',value:'antiLinks'},
        {name:'Anti-caps',value:'antiCaps'},{name:'Anti-duplicate messages',value:'antiDuplicate'},{name:'Anti-mass mentions',value:'antiMassMention'},
        {name:'Anti-nuke audit monitoring',value:'antiNuke'},{name:'Anti-webhook',value:'antiWebhook'},{name:'Anti-untrusted bot additions',value:'antiBotAdd'},
        {name:'Anti-young accounts',value:'antiAccountAge'},{name:'Dangerous role permissions',value:'antiDangerousPerms'},{name:'Anti-mass ban monitoring',value:'antiMassBan'},
        {name:'Role deletion monitoring',value:'antiRoleDelete'},{name:'Channel deletion monitoring',value:'antiChannelDelete'},{name:'Server setting change monitoring',value:'antiGuildUpdate'}))
      .addBooleanOption(o => o.setName('enabled').setDescription('Enable this defense').setRequired(true)))
    .addSubcommand(s => s.setName('backup-schedule').setDescription('Configure automatic structural backups (server owner only)')
      .addBooleanOption(o => o.setName('enabled').setDescription('Enable scheduled backups').setRequired(true))
      .addIntegerOption(o => o.setName('interval_hours').setDescription('Backup interval (1–168 hours)').setMinValue(1).setMaxValue(168))
      .addIntegerOption(o => o.setName('retention').setDescription('Number of backups to keep (1–100)').setMinValue(1).setMaxValue(100)))
    .addSubcommand(s => s.setName('trust').setDescription('Manage trusted users exempt from automated anti-nuke response')
      .addStringOption(o => o.setName('action').setDescription('Choose an action').setRequired(true).addChoices({name:'Add user',value:'add'},{name:'Remove user',value:'remove'},{name:'List trusted users',value:'list'}))
      .addUserOption(o => o.setName('user').setDescription('User to add or remove')))
    .addSubcommand(s => s.setName('raidmode').setDescription('Toggle temporary high-alert raid mode')
      .addBooleanOption(o => o.setName('enabled').setDescription('Enable raid mode').setRequired(true)))
    .addSubcommand(s => s.setName('panic').setDescription('Emergency lock or unlock all ordinary text channels')
      .addStringOption(o => o.setName('action').setDescription('Emergency action').setRequired(true).addChoices({name:'Lock all',value:'lock'},{name:'Unlock all',value:'unlock'}))
      .addBooleanOption(o => o.setName('confirm').setDescription('Confirm this affects all ordinary text channels').setRequired(true)))
    .addSubcommand(s => s.setName('config').setDescription('View or update protection settings')
      .addBooleanOption(o => o.setName('enabled').setDescription('Enable or disable Sentinel protections'))
      .addChannelOption(o => o.setName('log_channel').setDescription('Channel for security logs').addChannelTypes(ChannelType.GuildText))
      .addBooleanOption(o => o.setName('anti_spam').setDescription('Detect repeated messages'))
      .addBooleanOption(o => o.setName('anti_raid').setDescription('Detect unusual join bursts'))
      .addBooleanOption(o => o.setName('anti_invite').setDescription('Delete Discord invite links'))
      .addBooleanOption(o => o.setName('anti_mass_mention').setDescription('Detect mass mentions'))
      .addBooleanOption(o => o.setName('anti_nuke').setDescription('Detect destructive admin actions'))
      .addBooleanOption(o => o.setName('anti_links').setDescription('Delete external links from non-trusted users'))
      .addBooleanOption(o => o.setName('anti_caps').setDescription('Detect messages with excessive capital letters'))
      .addBooleanOption(o => o.setName('anti_duplicate').setDescription('Detect repeated duplicate messages'))
      .addBooleanOption(o => o.setName('anti_webhook').setDescription('Alert on webhook creation and deletion'))
      .addBooleanOption(o => o.setName('auto_response').setDescription('Allow configured automatic responses'))
      .addIntegerOption(o => o.setName('join_threshold').setDescription('Join burst threshold (3–30)').setMinValue(3).setMaxValue(30))
      .addIntegerOption(o => o.setName('spam_threshold').setDescription('Message count threshold (3–20)').setMinValue(3).setMaxValue(20))
      .addStringOption(o => o.setName('punishment').setDescription('Action after a message violation').addChoices({ name: 'Delete message only', value: 'delete' }, { name: 'Delete and timeout 10 minutes', value: 'timeout' })))
    .addSubcommand(s => s.setName('logs').setDescription('Show the latest security events').addIntegerOption(o => o.setName('count').setDescription('Number of events (1–10)').setMinValue(1).setMaxValue(10)))
    .addSubcommand(s => s.setName('backup').setDescription('Create a structural backup of roles, rooms and permissions'))
    .addSubcommand(s => s.setName('backups').setDescription('List recent backups'))
    .addSubcommand(s => s.setName('restore').setDescription('Restore rooms, categories, roles and permissions from a backup')
      .addStringOption(o => o.setName('backup_id').setDescription('Backup ID to restore').setRequired(true))
      .addBooleanOption(o => o.setName('confirm').setDescription('Confirm that restoration may create roles and channels').setRequired(true)))
    .addSubcommand(s => s.setName('lockdown').setDescription('Lock or unlock a text channel for @everyone')
      .addStringOption(o => o.setName('action').setDescription('Choose lockdown action').setRequired(true).addChoices({name:'Lock',value:'lock'},{name:'Unlock',value:'unlock'}))
      .addChannelOption(o => o.setName('channel').setDescription('Target text channel; defaults to this channel').addChannelTypes(ChannelType.GuildText)))
    .addSubcommand(s => s.setName('purge').setDescription('Delete recent messages in this channel')
      .addIntegerOption(o => o.setName('amount').setDescription('Number of messages (1–100)').setRequired(true).setMinValue(1).setMaxValue(100)))
    .addSubcommand(s => s.setName('userinfo').setDescription('Show information about a server member')
      .addUserOption(o => o.setName('user').setDescription('Member to inspect').setRequired(true)))
    .addSubcommand(s => s.setName('timeout').setDescription('Timeout a member')
      .addUserOption(o => o.setName('user').setDescription('Member to timeout').setRequired(true))
      .addIntegerOption(o => o.setName('minutes').setDescription('Duration in minutes (1–40320)').setRequired(true).setMinValue(1).setMaxValue(40320))
      .addStringOption(o => o.setName('reason').setDescription('Reason for the timeout').setMaxLength(300)))
    .addSubcommand(s => s.setName('kick').setDescription('Kick a member from the server')
      .addUserOption(o => o.setName('user').setDescription('Member to kick').setRequired(true))
      .addStringOption(o => o.setName('reason').setDescription('Reason for the kick').setMaxLength(300)))
    .addSubcommand(s => s.setName('ban').setDescription('Ban a member from the server')
      .addUserOption(o => o.setName('user').setDescription('Member to ban').setRequired(true))
      .addStringOption(o => o.setName('reason').setDescription('Reason for the ban').setMaxLength(300))
      .addIntegerOption(o => o.setName('delete_message_days').setDescription('Delete recent message history (0–7 days)').setMinValue(0).setMaxValue(7)))
    .addSubcommand(s => s.setName('slowmode').setDescription('Set a text channel slowmode')
      .addIntegerOption(o => o.setName('seconds').setDescription('Delay in seconds (0–21600)').setRequired(true).setMinValue(0).setMaxValue(21600))
      .addChannelOption(o => o.setName('channel').setDescription('Target channel; defaults to this channel').addChannelTypes(ChannelType.GuildText)))
    .addSubcommand(s => s.setName('scan').setDescription('Run a read-only server safety check'))
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild),
  new SlashCommandBuilder().setName('sentinel-admin').setDescription('Bot owner diagnostics')
    .addSubcommand(s => s.setName('stats').setDescription('Show bot and database stats'))
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
].map(c => c.toJSON());

function makeClient() {
  const client = new Client({
    intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent, GatewayIntentBits.GuildModeration],
    partials: [Partials.Channel, Partials.Message, Partials.GuildMember]
  });
  registerSecurityHandlers(client);

  // Rotate the public Discord presence through real, database-backed Sentinel stats.
  // Counts are refreshed every 60 seconds; the visible activity rotates every 20 seconds.
  let presenceItems = ['Protecting Discord servers'];
  let presenceIndex = 0;
  let statsRefreshInProgress = false;

  const applyPresence = () => {
    if (!client.user) return;
    const activity = presenceItems[presenceIndex % presenceItems.length];
    presenceIndex = (presenceIndex + 1) % presenceItems.length;
    client.user.setPresence({
      activities: [{ name: activity.slice(0, 128), type: ActivityType.Watching }],
      status: 'online'
    });
  };

  const refreshPresenceStats = async () => {
    if (statsRefreshInProgress || !client.user) return;
    statsRefreshInProgress = true;
    try {
      const serverCount = client.guilds.cache.size;
      const memberCount = client.guilds.cache.reduce((sum, guild) => sum + (guild.memberCount || 0), 0);
      const [configuredCount, backupCount] = await Promise.all([
        Settings.countDocuments({ enabled: true }).maxTimeMS(5000).exec(),
        Backup.countDocuments().maxTimeMS(5000).exec()
      ]);
      const compact = n => Number(n || 0).toLocaleString('en-US');
      presenceItems = [
        `Protecting ${compact(serverCount)} servers`,
        `${compact(backupCount)} backups secured`,
        `Guarding ${compact(memberCount)} members`,
        `Monitoring ${compact(configuredCount)} security profiles`,
        'Sentinel Security • /sentinel'
      ];
      applyPresence();
    } catch (error) {
      console.warn('[sentinel] Presence stats refresh failed:', error.message);
      presenceItems = [`Protecting ${client.guilds.cache.size} servers`, 'Sentinel Security • /sentinel'];
      applyPresence();
    } finally {
      statsRefreshInProgress = false;
    }
  };

  client.once('clientReady', async () => {
    console.log(`[sentinel] Logged in as ${client.user.tag}; guilds=${client.guilds.cache.size}`);
    await refreshPresenceStats();
    const statsTimer = setInterval(refreshPresenceStats, 60_000);
    const rotationTimer = setInterval(applyPresence, 20_000);
    statsTimer.unref?.();
    rotationTimer.unref?.();
  });
  client.on('guildCreate', () => { refreshPresenceStats().catch(() => {}); });
  client.on('guildDelete', () => { refreshPresenceStats().catch(() => {}); });

  client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;
    try {
      if (interaction.commandName === 'sentinel-admin') {
        const owners = (process.env.BOT_OWNER_IDS || '').split(',').map(x => x.trim()).filter(Boolean);
        if (!owners.includes(interaction.user.id)) return interaction.reply({ content: 'This command is restricted to the bot owner.', flags: MessageFlags.Ephemeral });
        const guildCount = client.guilds.cache.size;
        const settingsCount = await Settings.countDocuments();
        return interaction.reply({ content: `Sentinel online. Servers: ${guildCount}. Configured servers: ${settingsCount}. MongoDB: connected.`, flags: MessageFlags.Ephemeral });
      }
      if (interaction.commandName !== 'sentinel') return;
      if (!interaction.guild) return interaction.reply({ content: 'Use this command inside a server.', flags: MessageFlags.Ephemeral });
      if (!interaction.memberPermissions?.has(PermissionFlagsBits.ManageGuild)) return interaction.reply({ content: 'You need Manage Server permission.', flags: MessageFlags.Ephemeral });
      const sub = interaction.options.getSubcommand();
      const settings = await getSettings(interaction.guild);
      if (sub === 'security') {
        if (interaction.guild.ownerId !== interaction.user.id) return interaction.reply({ content: 'Only the actual server owner can change the security profile.', flags: MessageFlags.Ephemeral });
        const profile = interaction.options.getString('profile', true);
        const presets = {
          low: { antiSpam: true, antiRaid: true, antiInvite: true, antiMassMention: true, antiNuke: true, antiLinks: false, antiCaps: false, antiDuplicate: false, antiWebhook: true, antiBotAdd: true, antiAccountAge: false, antiDangerousPerms: true, antiMassBan: true, antiRoleDelete: true, antiChannelDelete: true, antiGuildUpdate: true, autoResponse: false, joinThreshold: 12, spamMessages: 8, mentionLimit: 8, punishment: 'delete' },
          medium: { antiSpam: true, antiRaid: true, antiInvite: true, antiMassMention: true, antiNuke: true, antiLinks: false, antiCaps: true, antiDuplicate: true, antiWebhook: true, antiBotAdd: true, antiAccountAge: false, antiDangerousPerms: true, antiMassBan: true, antiRoleDelete: true, antiChannelDelete: true, antiGuildUpdate: true, autoResponse: true, joinThreshold: 8, spamMessages: 6, mentionLimit: 5, punishment: 'timeout' },
          high: { antiSpam: true, antiRaid: true, antiInvite: true, antiMassMention: true, antiNuke: true, antiLinks: true, antiCaps: true, antiDuplicate: true, antiWebhook: true, antiBotAdd: true, antiAccountAge: true, antiDangerousPerms: true, antiMassBan: true, antiRoleDelete: true, antiChannelDelete: true, antiGuildUpdate: true, autoResponse: true, minAccountAgeHours: 24, joinThreshold: 5, spamMessages: 4, mentionLimit: 3, punishment: 'timeout' }
        };
        Object.assign(settings, presets[profile], { securityProfile: profile, enabled: true, updatedAt: new Date() });
        await saveSettings(settings);
        await logEvent(client, interaction.guild.id, 'Security profile changed', `${interaction.user.tag} selected ${profile.toUpperCase()} security.`, { severity: profile === 'high' ? 'critical' : 'warning', actorId: interaction.user.id });
        return interaction.reply({ content: `Security profile set to **${profile.toUpperCase()}**. Automatic responses: ${settings.autoResponse ? 'enabled' : 'disabled'}. Review exemptions and channel permissions with /sentinel trust and /sentinel scan.`, flags: MessageFlags.Ephemeral });
      }
      if (sub === 'features') {
        if (interaction.guild.ownerId !== interaction.user.id) return interaction.reply({ content: 'Only the actual server owner can change security defenses.', flags: MessageFlags.Ephemeral });
        const field = interaction.options.getString('feature', true);
        const enabled = interaction.options.getBoolean('enabled', true);
        settings[field] = enabled;
        settings.updatedAt = new Date();
        await saveSettings(settings);
        await logEvent(client, interaction.guild.id, 'Defense toggled', `${field} ${enabled ? 'enabled' : 'disabled'} by ${interaction.user.tag}.`, { severity: enabled ? 'info' : 'warning', actorId: interaction.user.id });
        return interaction.reply({ content: `**${field}** is now **${enabled ? 'enabled' : 'disabled'}** for this server.`, flags: MessageFlags.Ephemeral });
      }
      if (sub === 'backup-schedule') {
        if (interaction.guild.ownerId !== interaction.user.id) return interaction.reply({ content: 'Only the actual server owner can configure automatic backups.', flags: MessageFlags.Ephemeral });
        settings.autoBackupEnabled = interaction.options.getBoolean('enabled', true);
        const interval = interaction.options.getInteger('interval_hours');
        const retention = interaction.options.getInteger('retention');
        if (interval !== null) settings.autoBackupIntervalHours = interval;
        if (retention !== null) settings.backupRetention = retention;
        await saveSettings(settings);
        await logEvent(client, interaction.guild.id, 'Backup schedule changed', `Scheduled backups ${settings.autoBackupEnabled ? 'enabled' : 'disabled'}; interval ${settings.autoBackupIntervalHours}h; retention ${settings.backupRetention}.`, { severity: 'warning', actorId: interaction.user.id });
        return interaction.reply({ content: `Automatic structural backups **${settings.autoBackupEnabled ? 'enabled' : 'disabled'}**. Interval: every ${settings.autoBackupIntervalHours} hours. Retention: ${settings.backupRetention} backups. Backups require Sentinel to remain online and MongoDB to be available.`, flags: MessageFlags.Ephemeral });
      }
      if (sub === 'trust') {
        if (interaction.guild.ownerId !== interaction.user.id) return interaction.reply({ content: 'Only the actual server owner can manage trusted users.', flags: MessageFlags.Ephemeral });
        const action = interaction.options.getString('action', true); const user = interaction.options.getUser('user');
        if (action !== 'list' && !user) return interaction.reply({ content: 'Choose a user for add/remove.', flags: MessageFlags.Ephemeral });
        if (action === 'add' && !settings.trustedUserIds.includes(user.id)) settings.trustedUserIds.push(user.id);
        if (action === 'remove') settings.trustedUserIds = settings.trustedUserIds.filter(id => id !== user.id);
        await saveSettings(settings);
        if (action === 'list') return interaction.reply({ content: settings.trustedUserIds.length ? settings.trustedUserIds.map(id => `• <@${id}> (\`${id}\`)`).join('\n') : 'No trusted users configured.', flags: MessageFlags.Ephemeral });
        await logEvent(client, interaction.guild.id, `Trusted user ${action}`, `${interaction.user.tag} ${action}ed ${user.tag} in the trusted list.`, { severity: 'warning', actorId: interaction.user.id, targetId: user.id });
        return interaction.reply({ content: `${user.tag} ${action === 'add' ? 'added to' : 'removed from'} the trusted-user list. Trusted users are exempt from Sentinel's automatic anti-nuke punishment, not from Discord permissions or manual moderation.`, flags: MessageFlags.Ephemeral });
      }
      if (sub === 'raidmode') {
        if (interaction.guild.ownerId !== interaction.user.id) return interaction.reply({ content: 'Only the actual server owner can toggle raid mode.', flags: MessageFlags.Ephemeral });
        const enabled = interaction.options.getBoolean('enabled', true);
        settings.raidMode = enabled; settings.securityProfile = enabled ? 'high' : (settings.securityProfile === 'high' ? 'medium' : settings.securityProfile);
        if (enabled) Object.assign(settings, { antiRaid: true, antiSpam: true, antiInvite: true, antiMassMention: true, antiNuke: true, antiDuplicate: true, autoResponse: true, joinThreshold: 5, spamMessages: 4, mentionLimit: 3, punishment: 'timeout' });
        await saveSettings(settings);
        await logEvent(client, interaction.guild.id, 'Raid mode changed', `Raid mode ${enabled ? 'enabled' : 'disabled'} by ${interaction.user.tag}.`, { severity: enabled ? 'critical' : 'warning', actorId: interaction.user.id });
        return interaction.reply({ content: `Raid mode ${enabled ? '**enabled** — high-alert thresholds applied.' : '**disabled** — current profile settings retained.'}`, flags: MessageFlags.Ephemeral });
      }
      if (sub === 'panic') {
        if (interaction.guild.ownerId !== interaction.user.id) return interaction.reply({ content: 'Only the actual server owner can use emergency server-wide lockdown.', flags: MessageFlags.Ephemeral });
        if (!interaction.options.getBoolean('confirm', true)) return interaction.reply({ content: 'Cancelled. Set confirm to true to proceed.', flags: MessageFlags.Ephemeral });
        const action = interaction.options.getString('action', true);
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });
        const textChannels = await interaction.guild.channels.fetch();
        let changed = 0, failed = 0;
        if (action === 'lock') {
          const snapshot = [];
          for (const ch of textChannels.values()) {
            if (!ch || ![ChannelType.GuildText, ChannelType.GuildAnnouncement].includes(ch.type) || ch.isThread?.()) continue;
            try { const current = ch.permissionOverwrites.cache.get(interaction.guild.id); snapshot.push({ channelId: ch.id, sendMessages: current?.deny.has(PermissionFlagsBits.SendMessages) ? false : current?.allow.has(PermissionFlagsBits.SendMessages) ? true : null }); await ch.permissionOverwrites.edit(interaction.guild.roles.everyone, { SendMessages: false }, { reason: `Sentinel emergency lockdown by ${interaction.user.tag}` }); changed++; } catch { failed++; }
          }
          settings.lockdownSnapshot = snapshot; settings.lockdownActive = true; await saveSettings(settings);
        } else {
          if (!settings.lockdownActive || !Array.isArray(settings.lockdownSnapshot)) return interaction.editReply('No Sentinel lockdown snapshot exists. Sentinel will not blindly remove existing channel restrictions.');
          for (const row of settings.lockdownSnapshot) { const ch = textChannels.get(row.channelId); if (!ch) continue; try { await ch.permissionOverwrites.edit(interaction.guild.roles.everyone, { SendMessages: row.sendMessages === false ? false : row.sendMessages === true ? true : null }, { reason: `Sentinel emergency unlock by ${interaction.user.tag}` }); changed++; } catch { failed++; } }
          settings.lockdownActive = false; settings.lockdownSnapshot = []; await saveSettings(settings);
        }
        await logEvent(client, interaction.guild.id, `Emergency ${action}down`, `${interaction.user.tag} ran server-wide ${action}. Changed ${changed} channels; ${failed} failed.`, { severity: 'critical', actorId: interaction.user.id });
        return interaction.editReply(`Emergency ${action} complete. Channels changed: ${changed}. Failed: ${failed}. ${action === 'lock' ? 'Use /sentinel panic action:unlock confirm:true to restore recorded @everyone Send Messages settings.' : 'Recorded @everyone Send Messages settings restored.'}`);
      }
      if (sub === 'status') {
        const embed = new EmbedBuilder().setColor(settings.enabled ? 0x35b86b : 0x8a8a8a).setTitle('Sentinel protection status')
          .addFields({ name: 'Master switch', value: settings.enabled ? 'Enabled' : 'Disabled', inline: true }, { name: 'Anti-spam', value: String(settings.antiSpam), inline: true }, { name: 'Anti-raid', value: String(settings.antiRaid), inline: true }, { name: 'Anti-invite', value: String(settings.antiInvite), inline: true }, { name: 'Mass mentions', value: String(settings.antiMassMention), inline: true }, { name: 'Anti-nuke', value: String(settings.antiNuke), inline: true }, { name: 'Profile', value: String(settings.securityProfile || 'medium').toUpperCase(), inline: true }, { name: 'Auto-response', value: String(settings.autoResponse), inline: true }, { name: 'Anti-links', value: String(settings.antiLinks), inline: true }, { name: 'Anti-webhook', value: String(settings.antiWebhook), inline: true }, { name: 'Anti-bot-add', value: String(settings.antiBotAdd), inline: true }, { name: 'Dangerous permissions', value: String(settings.antiDangerousPerms), inline: true }, { name: 'Anti-account-age', value: String(settings.antiAccountAge), inline: true }, { name: 'Auto backups', value: `${settings.autoBackupEnabled ? 'Enabled' : 'Disabled'} · ${settings.autoBackupIntervalHours}h`, inline: true }, { name: 'Log channel', value: settings.logChannelId ? `<#${settings.logChannelId}>` : 'Not configured' })
          .setFooter({ text: 'Configure with /sentinel config' });
        return interaction.reply({ embeds: [embed], flags: MessageFlags.Ephemeral });
      }
      if (sub === 'config') {
        const pairs = [['enabled', 'enabled'], ['anti_spam', 'antiSpam'], ['anti_raid', 'antiRaid'], ['anti_invite', 'antiInvite'], ['anti_mass_mention', 'antiMassMention'], ['anti_nuke', 'antiNuke'], ['anti_links', 'antiLinks'], ['anti_caps', 'antiCaps'], ['anti_duplicate', 'antiDuplicate'], ['anti_webhook', 'antiWebhook'], ['auto_response', 'autoResponse']];
        for (const [option, field] of pairs) { const value = interaction.options.getBoolean(option); if (value !== null) settings[field] = value; }
        const channel = interaction.options.getChannel('log_channel'); if (channel) settings.logChannelId = channel.id;
        const joins = interaction.options.getInteger('join_threshold'); if (joins !== null) settings.joinThreshold = joins;
        const spam = interaction.options.getInteger('spam_threshold'); if (spam !== null) settings.spamMessages = spam;
        const punishment = interaction.options.getString('punishment'); if (punishment) settings.punishment = punishment;
        settings.guildName = interaction.guild.name; settings.updatedAt = new Date(); await saveSettings(settings);
        await logEvent(client, interaction.guild.id, 'Configuration updated', `Security settings updated by ${interaction.user.tag}.`);
        return interaction.reply({ content: 'Sentinel settings saved for this server.', flags: MessageFlags.Ephemeral });
      }
      if (sub === 'logs') {
        const count = interaction.options.getInteger('count') || 5;
        const events = await SecurityEvent.find({ guildId: interaction.guild.id }).sort({ createdAt: -1 }).limit(count).lean();
        const description = events.length ? events.map(e => `**${e.severity.toUpperCase()} · ${e.type}** — ${e.message.slice(0, 220)}\n<t:${Math.floor(new Date(e.createdAt).getTime()/1000)}:R>`).join('\n\n') : 'No security events recorded yet.';
        return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x5965f2).setTitle('Recent Sentinel events').setDescription(description.slice(0, 4000))], flags: MessageFlags.Ephemeral });
      }
      if (sub === 'backup') {
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });
        const saved = await createStructuralBackup(interaction.guild, interaction.user.id);
        await logEvent(client, interaction.guild.id, 'Backup created', `Structural backup ${saved.id} created by ${interaction.user.tag}.`);
        return interaction.editReply(`Structural backup created. ID: \`${saved.id}\`\nSaved supported roles, channels/categories, and permission overwrites. Restore with /sentinel restore. Messages, attachments, integrations, webhooks, invites, member role assignments, original IDs, and some Discord-specific settings cannot be restored.`);
      }
      if (sub === 'restore') {
        if (interaction.guild.ownerId !== interaction.user.id) return interaction.reply({ content: 'Only the actual Discord server owner can restore a backup.', flags: MessageFlags.Ephemeral });
        if (!interaction.options.getBoolean('confirm')) return interaction.reply({ content: 'Restore cancelled. Set confirm to true only when you are ready to recreate server structure.', flags: MessageFlags.Ephemeral });
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });
        const backupId = interaction.options.getString('backup_id', true);
        const backup = await Backup.findOne({ _id: backupId, guildId: interaction.guild.id }).lean();
        if (!backup) return interaction.editReply('Backup not found for this server. Use /sentinel backups to find a valid backup ID.');
        const me = interaction.guild.members.me;
        if (!me?.permissions.has(PermissionFlagsBits.ManageChannels) || !me.permissions.has(PermissionFlagsBits.ManageRoles)) return interaction.editReply('Sentinel needs Manage Channels and Manage Roles permissions to restore this backup.');
        const data = backup.data || {};
        const roleMap = new Map([[interaction.guild.id, interaction.guild.id]]);
        const channelMap = new Map();
        const errors = [];
        let rolesCreated = 0, channelsCreated = 0, overwritesApplied = 0;
        // Match existing roles by original ID first, then by name; never edit managed or @everyone roles.
        for (const r of [...(data.roles || [])].sort((a,b) => a.position - b.position)) {
          try {
            let role = interaction.guild.roles.cache.get(r.id) || interaction.guild.roles.cache.find(x => !x.managed && x.name === r.name);
            if (!role) {
              role = await interaction.guild.roles.create({ name: r.name, color: r.color, hoist: r.hoist, mentionable: r.mentionable, permissions: BigInt(r.permissions || '0'), reason: `Sentinel restore ${backup._id}` });
              rolesCreated++;
            } else if (!role.managed && role.editable) {
              await role.edit({ color: r.color, hoist: r.hoist, mentionable: r.mentionable, permissions: BigInt(r.permissions || '0'), reason: `Sentinel restore ${backup._id}` }).catch(() => {});
            }
            roleMap.set(r.id, role.id);
          } catch (e) { errors.push(`Role ${r.name}: ${e.message}`); }
        }
        try {
          const positions = (data.roles || []).filter(r => roleMap.has(r.id)).map(r => ({ role: roleMap.get(r.id), position: r.position })).filter(x => Number.isInteger(x.position));
          if (positions.length) await interaction.guild.roles.setPositions(positions);
        } catch (e) { errors.push(`Role positions: ${e.message}`); }
        const channelRows = [...(data.channels || [])].sort((a,b) => {
          const ac = a.type === ChannelType.GuildCategory ? 0 : 1, bc = b.type === ChannelType.GuildCategory ? 0 : 1;
          return ac - bc || (a.position || 0) - (b.position || 0);
        });
        // Create missing categories first so child channels can be re-parented.
        for (const c of channelRows) {
          try {
            let channel = interaction.guild.channels.cache.get(c.id) || interaction.guild.channels.cache.find(x => x.name === c.name && x.type === c.type);
            if (!channel) {
              const opts = { name: c.name, type: c.type, reason: `Sentinel restore ${backup._id}` };
              if (c.type !== ChannelType.GuildCategory && c.parentId && channelMap.has(c.parentId)) opts.parent = channelMap.get(c.parentId);
              if ([ChannelType.GuildText, ChannelType.GuildAnnouncement].includes(c.type)) { if (c.topic) opts.topic = c.topic; opts.nsfw = !!c.nsfw; opts.rateLimitPerUser = c.rateLimitPerUser || 0; }
              if ([ChannelType.GuildVoice, ChannelType.GuildStageVoice].includes(c.type)) { if (c.bitrate) opts.bitrate = c.bitrate; if (c.userLimit != null) opts.userLimit = c.userLimit; if (c.rtcRegion) opts.rtcRegion = c.rtcRegion; }
              channel = await interaction.guild.channels.create(opts);
              channelsCreated++;
            }
            channelMap.set(c.id, channel.id);
          } catch (e) { errors.push(`Channel ${c.name}: ${e.message}`); }
        }
        // Restore channel parents, order, and overwrite entries with remapped role IDs.
        for (const c of channelRows) {
          const channelId = channelMap.get(c.id); const channel = channelId && interaction.guild.channels.cache.get(channelId);
          if (!channel) continue;
          try {
            const edit = {};
            if (c.type !== ChannelType.GuildCategory && c.parentId && channelMap.has(c.parentId)) edit.parent = channelMap.get(c.parentId);
            if (Number.isInteger(c.position)) edit.position = c.position;
            if (Object.keys(edit).length) await channel.edit(edit, `Sentinel restore ${backup._id}`);
            if (Array.isArray(c.permissionOverwrites)) {
              const overwrites = c.permissionOverwrites.flatMap(o => {
                let targetId = o.id;
                if (o.type === 0) {
                  targetId = roleMap.get(o.id) || (interaction.guild.roles.cache.has(o.id) ? o.id : null);
                } else if (!interaction.guild.members.cache.has(o.id)) {
                  return []; // Skip member overwrites for users who are no longer in this server.
                }
                if (!targetId) return []; // A role could not be recreated; don't apply a stale role ID.
                return [{ id: targetId, type: o.type, allow: BigInt(o.allow || '0'), deny: BigInt(o.deny || '0') }];
              });
              await channel.permissionOverwrites.set(overwrites, `Sentinel restore ${backup._id}`);
              overwritesApplied++;
            }
          } catch (e) { errors.push(`Permissions/position ${c.name}: ${e.message}`); }
        }
        await logEvent(client, interaction.guild.id, 'Backup restored', `Backup ${backup._id} restored by ${interaction.user.tag}: ${rolesCreated} roles and ${channelsCreated} channels created; ${errors.length} errors.`, { severity: errors.length ? 'warning' : 'critical', actorId: interaction.user.id });
        const summary = [`Restore finished for backup ${backup._id}.`, `Created roles: ${rolesCreated}`, `Created channels: ${channelsCreated}`, `Permission sets processed: ${overwritesApplied}`, `Errors: ${errors.length}`].join('\n');
        const errorText = errors.length ? '\n\nFirst errors:\n' + errors.slice(0, 8).map(e => `• ${e}`).join('\n') : '';
        return interaction.editReply((summary + errorText + '\n\nNote: Discord assigns new IDs to recreated objects; messages and attachments are not recoverable.').slice(0, 1950));
      }
      if (sub === 'lockdown') {
        if (!interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels)) return interaction.reply({ content: 'You need Manage Channels permission.', flags: MessageFlags.Ephemeral });
        const channel = interaction.options.getChannel('channel') || interaction.channel;
        if (!channel?.isTextBased() || !channel.permissionOverwrites) return interaction.reply({ content: 'Choose a text channel.', flags: MessageFlags.Ephemeral });
        const action = interaction.options.getString('action', true);
        await channel.permissionOverwrites.edit(interaction.guild.roles.everyone, { SendMessages: action === 'unlock' ? null : false, AddReactions: action === 'unlock' ? null : false }, { reason: `Sentinel ${action} requested by ${interaction.user.tag}` });
        await logEvent(client, interaction.guild.id, `Channel ${action}down`, `${channel} was ${action === 'lock' ? 'locked' : 'unlocked'} by ${interaction.user.tag}.`, { severity: 'warning', actorId: interaction.user.id });
        return interaction.reply({ content: `${channel} ${action === 'lock' ? 'locked' : 'unlocked'} for @everyone.`, flags: MessageFlags.Ephemeral });
      }
      if (sub === 'purge') {
        if (!interaction.memberPermissions?.has(PermissionFlagsBits.ManageMessages)) return interaction.reply({ content: 'You need Manage Messages permission.', flags: MessageFlags.Ephemeral });
        if (!interaction.channel?.bulkDelete) return interaction.reply({ content: 'This channel does not support bulk deletion.', flags: MessageFlags.Ephemeral });
        const amount = interaction.options.getInteger('amount', true);
        const deleted = await interaction.channel.bulkDelete(amount, true);
        await logEvent(client, interaction.guild.id, 'Messages purged', `${interaction.user.tag} bulk-deleted ${deleted.size} messages in #${interaction.channel.name}.`, { severity: 'warning', actorId: interaction.user.id });
        return interaction.reply({ content: `Deleted ${deleted.size} recent messages. Messages older than 14 days are skipped by Discord.`, flags: MessageFlags.Ephemeral });
      }
      if (sub === 'userinfo') {
        const user = interaction.options.getUser('user', true);
        const member = await interaction.guild.members.fetch(user.id).catch(() => null);
        if (!member) return interaction.reply({ content: 'That user is not a member of this server.', flags: MessageFlags.Ephemeral });
        const embed = new EmbedBuilder().setColor(0xff3154).setTitle(`Member • ${user.tag}`).setThumbnail(user.displayAvatarURL()).addFields(
          { name: 'User ID', value: user.id, inline: true }, { name: 'Account created', value: `<t:${Math.floor(user.createdTimestamp/1000)}:R>`, inline: true },
          { name: 'Joined server', value: member.joinedTimestamp ? `<t:${Math.floor(member.joinedTimestamp/1000)}:R>` : 'Unknown', inline: true },
          { name: 'Highest role', value: member.roles.highest?.name || 'None', inline: true }, { name: 'Timed out', value: member.communicationDisabledUntilTimestamp ? `<t:${Math.floor(member.communicationDisabledUntilTimestamp/1000)}:R>` : 'No', inline: true }
        );
        return interaction.reply({ embeds: [embed], flags: MessageFlags.Ephemeral });
      }
      if (sub === 'timeout' || sub === 'kick' || sub === 'ban') {
        const required = sub === 'timeout' ? PermissionFlagsBits.ModerateMembers : sub === 'kick' ? PermissionFlagsBits.KickMembers : PermissionFlagsBits.BanMembers;
        if (!interaction.memberPermissions?.has(required)) return interaction.reply({ content: `You need ${sub === 'timeout' ? 'Timeout Members' : sub === 'kick' ? 'Kick Members' : 'Ban Members'} permission.`, flags: MessageFlags.Ephemeral });
        const user = interaction.options.getUser('user', true);
        const reason = interaction.options.getString('reason') || `Action requested by ${interaction.user.tag}`;
        const member = await interaction.guild.members.fetch(user.id).catch(() => null);
        if (!member) return interaction.reply({ content: 'That user is not a member of this server.', flags: MessageFlags.Ephemeral });
        if (user.id === interaction.user.id || user.id === interaction.guild.ownerId) return interaction.reply({ content: 'You cannot moderate yourself or the server owner.', flags: MessageFlags.Ephemeral });
        if (!member.moderatable && sub === 'timeout' || !member.kickable && sub === 'kick' || !member.bannable && sub === 'ban') return interaction.reply({ content: 'Sentinel cannot moderate this member. Check the bot role hierarchy and permissions.', flags: MessageFlags.Ephemeral });
        if (sub === 'timeout') await member.timeout(interaction.options.getInteger('minutes', true) * 60_000, reason);
        if (sub === 'kick') await member.kick(reason);
        if (sub === 'ban') await interaction.guild.members.ban(user.id, { reason, deleteMessageSeconds: (interaction.options.getInteger('delete_message_days') || 0) * 86400 });
        await logEvent(client, interaction.guild.id, `Member ${sub}`, `${user.tag} (${user.id}) was ${sub === 'timeout' ? `timed out for ${interaction.options.getInteger('minutes')} minutes` : sub === 'kick' ? 'kicked' : 'banned'} by ${interaction.user.tag}. Reason: ${reason}`, { severity: 'warning', actorId: interaction.user.id, targetId: user.id });
        return interaction.reply({ content: `Action completed: ${user.tag} — ${sub}.`, flags: MessageFlags.Ephemeral });
      }
      if (sub === 'slowmode') {
        if (!interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels)) return interaction.reply({ content: 'You need Manage Channels permission.', flags: MessageFlags.Ephemeral });
        const channel = interaction.options.getChannel('channel') || interaction.channel;
        if (!channel?.setRateLimitPerUser) return interaction.reply({ content: 'Choose a text channel.', flags: MessageFlags.Ephemeral });
        const seconds = interaction.options.getInteger('seconds', true);
        await channel.setRateLimitPerUser(seconds, `Sentinel slowmode set by ${interaction.user.tag}`);
        await logEvent(client, interaction.guild.id, 'Slowmode updated', `#${channel.name} slowmode set to ${seconds}s by ${interaction.user.tag}.`, { actorId: interaction.user.id });
        return interaction.reply({ content: `Slowmode for ${channel} set to ${seconds} seconds.`, flags: MessageFlags.Ephemeral });
      }
      if (sub === 'scan') {
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });
        await interaction.guild.roles.fetch();
        await interaction.guild.channels.fetch();
        const adminRoles = interaction.guild.roles.cache.filter(r => r.permissions.has(PermissionFlagsBits.Administrator) && !r.managed);
        const everyone = interaction.guild.roles.everyone;
        const me = interaction.guild.members.me;
        const findings = [
          `**Roles:** ${interaction.guild.roles.cache.size - 1} (Administrator roles: ${adminRoles.size})`,
          `**Channels:** ${interaction.guild.channels.cache.size}`,
          `**@everyone Administrator:** ${everyone.permissions.has(PermissionFlagsBits.Administrator) ? 'YES — review immediately' : 'No'}`,
          `**Bot Manage Roles:** ${me?.permissions.has(PermissionFlagsBits.ManageRoles) ? 'Available' : 'Missing'}`,
          `**Bot Manage Channels:** ${me?.permissions.has(PermissionFlagsBits.ManageChannels) ? 'Available' : 'Missing'}`,
          `**Security logging:** ${settings.logChannelId ? `<#${settings.logChannelId}>` : 'Not configured'}`,
          `**Protection:** ${settings.enabled ? 'Enabled' : 'Disabled'}`
        ];
        return interaction.editReply({ embeds: [new EmbedBuilder().setColor(0xff3154).setTitle('Sentinel safety scan').setDescription(findings.join('\n')).setFooter({ text: 'Read-only scan: review flagged settings manually.' })] });
      }
      if (sub === 'backups') {
        const items = await Backup.find({ guildId: interaction.guild.id }).sort({ createdAt: -1 }).limit(10).lean();
        return interaction.reply({ content: items.length ? items.map(b => `• ${b._id} — <t:${Math.floor(new Date(b.createdAt).getTime()/1000)}:R> — by <@${b.createdBy}>`).join('\n') : 'No backups found.', flags: MessageFlags.Ephemeral });
      }
    } catch (error) {
      console.error('[interaction]', error);
      const payload = { content: 'Sentinel encountered an error. Check the application logs.', flags: MessageFlags.Ephemeral };
      if (interaction.deferred || interaction.replied) await interaction.followUp(payload).catch(() => {}); else await interaction.reply(payload).catch(() => {});
    }
  });
  return client;
}

async function registerCommands(clientId, token) {
  const rest = new REST({ version: '10' }).setToken(token);

  // Sentinel is a multi-server bot: commands must be registered globally,
  // not only against DISCORD_TEST_GUILD_ID.
  await rest.put(Routes.applicationCommands(clientId), { body: commands });
  console.log(`[sentinel] Registered ${commands.length} global slash commands.`);

  // If an older build registered test-guild commands, remove that duplicate
  // set so the test server uses the same global commands as every other server.
  const testGuildId = process.env.DISCORD_TEST_GUILD_ID;
  if (testGuildId) {
    try {
      await rest.put(Routes.applicationGuildCommands(clientId, testGuildId), { body: [] });
      console.log('[sentinel] Cleared legacy test-guild commands; global commands are active.');
    } catch (error) {
      console.warn('[sentinel] Could not clear legacy test-guild commands:', error.message);
    }
  }
}

module.exports = { makeClient, registerCommands };
