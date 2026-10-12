const {
  Client, GatewayIntentBits, Partials, REST, Routes, SlashCommandBuilder,
  PermissionFlagsBits, EmbedBuilder, ChannelType
} = require('discord.js');
const { Settings, SecurityEvent, Backup } = require('./models');
const { getSettings, logEvent, registerSecurityHandlers } = require('./security');

const commands = [
  new SlashCommandBuilder().setName('sentinel').setDescription('Sentinel security tools')
    .addSubcommand(s => s.setName('status').setDescription('Show Sentinel status and enabled defenses'))
    .addSubcommand(s => s.setName('config').setDescription('View or update protection settings')
      .addBooleanOption(o => o.setName('enabled').setDescription('Enable or disable Sentinel protections'))
      .addChannelOption(o => o.setName('log_channel').setDescription('Channel for security logs').addChannelTypes(ChannelType.GuildText))
      .addBooleanOption(o => o.setName('anti_spam').setDescription('Detect repeated messages'))
      .addBooleanOption(o => o.setName('anti_raid').setDescription('Detect unusual join bursts'))
      .addBooleanOption(o => o.setName('anti_invite').setDescription('Delete Discord invite links'))
      .addBooleanOption(o => o.setName('anti_mass_mention').setDescription('Detect mass mentions'))
      .addBooleanOption(o => o.setName('anti_nuke').setDescription('Alert on repeated channel/role deletion'))
      .addIntegerOption(o => o.setName('join_threshold').setDescription('Join burst threshold (3–30)').setMinValue(3).setMaxValue(30))
      .addIntegerOption(o => o.setName('spam_threshold').setDescription('Message count threshold (3–20)').setMinValue(3).setMaxValue(20))
      .addStringOption(o => o.setName('punishment').setDescription('Action after a message violation').addChoices({ name: 'Delete message only', value: 'delete' }, { name: 'Delete and timeout 10 minutes', value: 'timeout' })))
    .addSubcommand(s => s.setName('logs').setDescription('Show the latest security events').addIntegerOption(o => o.setName('count').setDescription('Number of events (1–10)').setMinValue(1).setMaxValue(10)))
    .addSubcommand(s => s.setName('backup').setDescription('Create a metadata backup of roles, channels and settings'))
    .addSubcommand(s => s.setName('backups').setDescription('List recent backups'))
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
  client.once('ready', () => console.log(`[sentinel] Logged in as ${client.user.tag}; guilds=${client.guilds.cache.size}`));
  client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;
    try {
      if (interaction.commandName === 'sentinel-admin') {
        const owners = (process.env.BOT_OWNER_IDS || '').split(',').map(x => x.trim()).filter(Boolean);
        if (!owners.includes(interaction.user.id)) return interaction.reply({ content: 'This command is restricted to the bot owner.', ephemeral: true });
        const guildCount = client.guilds.cache.size;
        const settingsCount = await Settings.countDocuments();
        return interaction.reply({ content: `Sentinel online. Servers: ${guildCount}. Configured servers: ${settingsCount}. MongoDB: connected.`, ephemeral: true });
      }
      if (interaction.commandName !== 'sentinel') return;
      if (!interaction.guild) return interaction.reply({ content: 'Use this command inside a server.', ephemeral: true });
      if (!interaction.memberPermissions?.has(PermissionFlagsBits.ManageGuild)) return interaction.reply({ content: 'You need Manage Server permission.', ephemeral: true });
      const sub = interaction.options.getSubcommand();
      const settings = await getSettings(interaction.guild);
      if (sub === 'status') {
        const embed = new EmbedBuilder().setColor(settings.enabled ? 0x35b86b : 0x8a8a8a).setTitle('Sentinel protection status')
          .addFields({ name: 'Master switch', value: settings.enabled ? 'Enabled' : 'Disabled', inline: true }, { name: 'Anti-spam', value: String(settings.antiSpam), inline: true }, { name: 'Anti-raid', value: String(settings.antiRaid), inline: true }, { name: 'Anti-invite', value: String(settings.antiInvite), inline: true }, { name: 'Mass mentions', value: String(settings.antiMassMention), inline: true }, { name: 'Anti-nuke alerts', value: String(settings.antiNuke), inline: true }, { name: 'Log channel', value: settings.logChannelId ? `<#${settings.logChannelId}>` : 'Not configured' })
          .setFooter({ text: 'Configure with /sentinel config' });
        return interaction.reply({ embeds: [embed], ephemeral: true });
      }
      if (sub === 'config') {
        const pairs = [['enabled', 'enabled'], ['anti_spam', 'antiSpam'], ['anti_raid', 'antiRaid'], ['anti_invite', 'antiInvite'], ['anti_mass_mention', 'antiMassMention'], ['anti_nuke', 'antiNuke']];
        for (const [option, field] of pairs) { const value = interaction.options.getBoolean(option); if (value !== null) settings[field] = value; }
        const channel = interaction.options.getChannel('log_channel'); if (channel) settings.logChannelId = channel.id;
        const joins = interaction.options.getInteger('join_threshold'); if (joins !== null) settings.joinThreshold = joins;
        const spam = interaction.options.getInteger('spam_threshold'); if (spam !== null) settings.spamMessages = spam;
        const punishment = interaction.options.getString('punishment'); if (punishment) settings.punishment = punishment;
        settings.guildName = interaction.guild.name; settings.updatedAt = new Date(); await settings.save();
        await logEvent(client, interaction.guild.id, 'Configuration updated', `Security settings updated by ${interaction.user.tag}.`);
        return interaction.reply({ content: 'Sentinel settings saved for this server.', ephemeral: true });
      }
      if (sub === 'logs') {
        const count = interaction.options.getInteger('count') || 5;
        const events = await SecurityEvent.find({ guildId: interaction.guild.id }).sort({ createdAt: -1 }).limit(count).lean();
        const description = events.length ? events.map(e => `**${e.severity.toUpperCase()} · ${e.type}** — ${e.message.slice(0, 220)}\n<t:${Math.floor(new Date(e.createdAt).getTime()/1000)}:R>`).join('\n\n') : 'No security events recorded yet.';
        return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x5965f2).setTitle('Recent Sentinel events').setDescription(description.slice(0, 4000))], ephemeral: true });
      }
      if (sub === 'backup') {
        await interaction.deferReply({ ephemeral: true });
        const roles = interaction.guild.roles.cache.filter(r => r.id !== interaction.guild.id).map(r => ({ id: r.id, name: r.name, color: r.color, hoist: r.hoist, mentionable: r.mentionable, permissions: r.permissions.bitfield.toString(), position: r.position }));
        const channels = interaction.guild.channels.cache.map(c => ({ id: c.id, name: c.name, type: c.type, parentId: c.parentId || null, position: c.position, topic: 'topic' in c ? c.topic : null, nsfw: 'nsfw' in c ? c.nsfw : false }));
        const saved = await Backup.create({ guildId: interaction.guild.id, createdBy: interaction.user.id, data: { guildName: interaction.guild.name, roles, channels, settings: settings.toObject() } });
        await logEvent(client, interaction.guild.id, 'Backup created', `Metadata backup ${saved.id} created by ${interaction.user.tag}.`);
        return interaction.editReply(`Backup created: ${saved.id}. This is a metadata backup; it does not include messages, files, or role/channel permission overwrites and is not an automatic restore point.`);
      }
      if (sub === 'backups') {
        const items = await Backup.find({ guildId: interaction.guild.id }).sort({ createdAt: -1 }).limit(10).lean();
        return interaction.reply({ content: items.length ? items.map(b => `• ${b._id} — <t:${Math.floor(new Date(b.createdAt).getTime()/1000)}:R> — by <@${b.createdBy}>`).join('\n') : 'No backups found.', ephemeral: true });
      }
    } catch (error) {
      console.error('[interaction]', error);
      const payload = { content: 'Sentinel encountered an error. Check the application logs.', ephemeral: true };
      if (interaction.deferred || interaction.replied) await interaction.followUp(payload).catch(() => {}); else await interaction.reply(payload).catch(() => {});
    }
  });
  return client;
}

async function registerCommands(clientId, token) {
  const rest = new REST({ version: '10' }).setToken(token);
  if (process.env.DISCORD_TEST_GUILD_ID) {
    await rest.put(Routes.applicationGuildCommands(clientId, process.env.DISCORD_TEST_GUILD_ID), { body: commands });
    console.log('[sentinel] Registered guild commands for test guild.');
  } else {
    await rest.put(Routes.applicationCommands(clientId), { body: commands });
    console.log('[sentinel] Registered global slash commands (propagation may take time).');
  }
}

module.exports = { makeClient, registerCommands };
