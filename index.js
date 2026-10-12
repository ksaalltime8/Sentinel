require('dotenv').config();
const mongoose = require('mongoose');
const { makeClient, registerCommands } = require('./src/bot');
const { createDashboard } = require('./src/dashboard');

const required = ['DISCORD_TOKEN', 'DISCORD_CLIENT_ID', 'MONGODB_URI', 'SESSION_SECRET', 'DASHBOARD_URL', 'DISCORD_CLIENT_SECRET'];
const missing = required.filter(k => !process.env[k] || process.env[k].startsWith('replace_me') || process.env[k].includes('example.mongodb.net'));
if (missing.length) {
  console.error(`[sentinel] Missing or placeholder environment variables: ${missing.join(', ')}`);
  console.error('[sentinel] Copy .env.example values into Hostinger environment variables before deploying.');
  process.exit(1);
}
if (process.env.SESSION_SECRET.length < 32) { console.error('[sentinel] SESSION_SECRET must be at least 32 characters.'); process.exit(1); }

async function start() {
  await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 15000 });
  console.log('[sentinel] MongoDB connected');
  const client = makeClient();
  await registerCommands(process.env.DISCORD_CLIENT_ID, process.env.DISCORD_TOKEN);
  const app = createDashboard(client);
  const port = Number(process.env.PORT) || 3000;
  const server = app.listen(port, '0.0.0.0', () => console.log(`[sentinel] Dashboard listening on ${port}`));
  await client.login(process.env.DISCORD_TOKEN);

  const shutdown = async signal => {
    console.log(`[sentinel] ${signal} received; shutting down`);
    server.close(); client.destroy(); await mongoose.disconnect(); process.exit(0);
  };
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT', () => shutdown('SIGINT'));
}
start().catch(error => { console.error('[sentinel] Startup failed:', error); process.exit(1); });
