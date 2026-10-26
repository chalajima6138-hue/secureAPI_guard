'use strict';
const { loadConfig, validateConfig } = require('./config');
const { createApp } = require('./app');

const config = loadConfig();
const problems = validateConfig(config);
if (problems.length) {
  console.error('Refusing to start with unsafe configuration:');
  problems.forEach((p) => console.error(` - ${p}`));
  process.exit(1);
}

const { app } = createApp({ config });
const server = app.listen(config.port, config.host, () => {
  console.log(`SecureAPI Guard listening on http://${config.host}:${config.port} (${config.nodeEnv})`);
  if (config.host !== '127.0.0.1') console.warn('Warning: listening on a non-loopback address. Put TLS in front before exposing this publicly.');
});
const shutdown = () => server.close(() => process.exit(0));
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
