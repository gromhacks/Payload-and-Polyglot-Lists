const express = require('express');
const { createClient } = require('redis');

const app = express();
app.use(express.urlencoded({ extended: false }));

let redisClient;

async function initRedis() {
  redisClient = createClient({ url: 'redis://redis:6379' });
  redisClient.on('error', (err) => console.error('Redis error:', err));
  await redisClient.connect();
  console.log('Connected to Redis');
}

app.get('/health', (req, res) => res.send('ok'));

app.post('/eval', async (req, res) => {
  const start = performance.now();
  try {
    const result = await redisClient.eval(req.body.input || '', { keys: [], arguments: [] });
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: String(result), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.post('/command', async (req, res) => {
  const start = performance.now();
  try {
    const parts = (req.body.input || '').split(' ');
    const result = await redisClient.sendCommand(parts);
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: String(result), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

initRedis().then(() => {
  app.listen(8080, () => console.log('nosql-redis testbed listening on 8080'));
}).catch((err) => {
  console.error('Failed to connect to Redis:', err);
  process.exit(1);
});
