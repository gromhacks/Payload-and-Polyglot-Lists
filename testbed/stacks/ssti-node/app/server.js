const express = require('express');
const ejs = require('ejs');
const nunjucks = require('nunjucks');
const handlebars = require('handlebars');
const pug = require('pug');

const app = express();
app.use(express.urlencoded({ extended: false }));

app.get('/health', (req, res) => res.send('ok'));

app.post('/ejs', (req, res) => {
  const start = performance.now();
  try {
    const output = ejs.render(req.body.input || '');
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: String(output), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.post('/nunjucks', (req, res) => {
  const start = performance.now();
  try {
    const output = nunjucks.renderString(req.body.input || '');
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: String(output), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.post('/handlebars', (req, res) => {
  const start = performance.now();
  try {
    const template = handlebars.compile(req.body.input || '');
    const output = template({});
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: String(output), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.post('/pug', (req, res) => {
  const start = performance.now();
  try {
    const output = pug.render(req.body.input || '');
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: String(output), error: null, time_ms });
  } catch (e) {
    const time_ms = Math.round((performance.now() - start) * 100) / 100;
    res.json({ output: null, error: e.message, time_ms });
  }
});

app.listen(8080, () => console.log('ssti-node testbed listening on 8080'));
