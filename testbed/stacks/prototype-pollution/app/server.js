const express = require('express');
const ejs = require('ejs');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Intentionally vulnerable deep merge - does NOT filter __proto__ or constructor
function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.get('/health', (req, res) => res.send('ok'));

app.post('/merge', (req, res) => {
  const start = performance.now();
  try {
    const obj = {};
    deepMerge(obj, req.body);
    const polluted = ({}).polluted;
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({
      output: JSON.stringify(obj),
      polluted: polluted !== undefined ? String(polluted) : null,
      error: null,
      time_ms
    });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.post('/ejs-render', (req, res) => {
  const start = performance.now();
  try {
    const options = {};
    deepMerge(options, req.body);
    const template = options.template || 'Hello <%= name %>';
    const data = options.data || { name: 'world' };
    const output = ejs.render(template, data, options);
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: String(output), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.listen(8080, () => console.log('prototype-pollution testbed listening on 8080'));
