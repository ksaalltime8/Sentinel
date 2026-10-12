const mongoose = require('mongoose');

const settingsSchema = new mongoose.Schema({
  guildId: { type: String, unique: true, index: true, required: true },
  guildName: { type: String, default: 'Unknown server' },
  enabled: { type: Boolean, default: true },
  logChannelId: { type: String, default: '' },
  alertChannelId: { type: String, default: '' },
  antiSpam: { type: Boolean, default: true },
  antiRaid: { type: Boolean, default: true },
  antiInvite: { type: Boolean, default: true },
  antiMassMention: { type: Boolean, default: true },
  antiNuke: { type: Boolean, default: true },
  joinThreshold: { type: Number, default: 8, min: 3, max: 30 },
  joinWindowSeconds: { type: Number, default: 10, min: 5, max: 60 },
  spamMessages: { type: Number, default: 6, min: 3, max: 20 },
  spamWindowSeconds: { type: Number, default: 7, min: 3, max: 30 },
  mentionLimit: { type: Number, default: 5, min: 3, max: 20 },
  punishment: { type: String, enum: ['delete', 'timeout'], default: 'timeout' },
  updatedAt: { type: Date, default: Date.now }
}, { minimize: false });

const eventSchema = new mongoose.Schema({
  guildId: { type: String, index: true, required: true },
  type: { type: String, required: true },
  message: { type: String, required: true, maxlength: 1000 },
  actorId: { type: String, default: '' },
  targetId: { type: String, default: '' },
  severity: { type: String, enum: ['info', 'warning', 'critical'], default: 'info' },
  createdAt: { type: Date, default: Date.now, index: true }
});
eventSchema.index({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 90 });

const backupSchema = new mongoose.Schema({
  guildId: { type: String, index: true, required: true },
  createdBy: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  data: { type: mongoose.Schema.Types.Mixed, required: true }
});

module.exports = {
  Settings: mongoose.models.Settings || mongoose.model('Settings', settingsSchema),
  SecurityEvent: mongoose.models.SecurityEvent || mongoose.model('SecurityEvent', eventSchema),
  Backup: mongoose.models.Backup || mongoose.model('Backup', backupSchema)
};
