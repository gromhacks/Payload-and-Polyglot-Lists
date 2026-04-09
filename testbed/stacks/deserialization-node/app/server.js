const express = require('express');
const serialize = require('node-serialize');
const yaml = require('js-yaml');
const funcster = require('funcster');

const app = express();
app.use(express.urlencoded({ extended: false }));

app.get('/health', (req, res) => res.send('ok'));

app.post('/funcster', (req, res) => {
  const start = performance.now();
  try {
    const result = funcster.deepDeserialize(JSON.parse(req.body.input || '{}'));
    // Invoke any deserialized functions (simulates real usage where
    // deserialized callbacks/handlers get called)
    let output = {};
    for (const [k, v] of Object.entries(result || {})) {
      output[k] = typeof v === 'function' ? v() : v;
    }
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: JSON.stringify(output), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.post('/unserialize', (req, res) => {
  const start = performance.now();
  try {
    const result = serialize.unserialize(req.body.input || '{}');
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: JSON.stringify(result), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.post('/yaml', (req, res) => {
  const start = performance.now();
  try {
    const result = yaml.load(req.body.input || '');
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: JSON.stringify(result), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.listen(8080, () => console.log('deserialization-node testbed listening on 8080'));
