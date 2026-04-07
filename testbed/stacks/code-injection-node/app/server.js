const express = require('express');
const vm = require('vm');

const app = express();
app.use(express.urlencoded({ extended: false }));

app.get('/health', (req, res) => res.send('ok'));

app.post('/eval', (req, res) => {
  const start = performance.now();
  try {
    const result = eval(req.body.input || '');
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: String(result), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.post('/function', (req, res) => {
  const start = performance.now();
  try {
    const result = new Function(req.body.input || '')();
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: String(result), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.post('/vm', (req, res) => {
  const start = performance.now();
  try {
    const result = vm.runInNewContext(req.body.input || '', {
      require: require,
      process: process,
      console: console
    });
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: String(result), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.listen(8080, () => console.log('code-injection-node testbed listening on 8080'));
