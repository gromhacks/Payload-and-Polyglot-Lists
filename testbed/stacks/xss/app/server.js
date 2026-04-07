const express = require('express');
const app = express();

app.use(express.urlencoded({ extended: false }));

app.get('/health', (req, res) => res.send('ok'));

app.post('/reflected', (req, res) => {
  const input = req.body.input || '';
  res.type('text/html').send(`<div>${input}</div>`);
});

app.post('/attr-double', (req, res) => {
  const input = req.body.input || '';
  res.type('text/html').send(`<input type="text" value="${input}">`);
});

app.post('/attr-single', (req, res) => {
  const input = req.body.input || '';
  res.type('text/html').send(`<input type='text' value='${input}'>`);
});

app.post('/script-string', (req, res) => {
  const input = req.body.input || '';
  res.type('text/html').send(`<script>var x = "${input}";</script>`);
});

app.post('/href', (req, res) => {
  const input = req.body.input || '';
  res.type('text/html').send(`<a href="${input}">click</a>`);
});

app.post('/textarea', (req, res) => {
  const input = req.body.input || '';
  res.type('text/html').send(`<textarea>${input}</textarea>`);
});

app.post('/json', (req, res) => {
  const start = performance.now();
  const input = req.body.input || '';
  const time_ms = Math.round((performance.now() - start) * 100) / 100;
  res.json({ output: input, error: null, time_ms });
});

app.listen(8080, () => console.log('xss testbed listening on 8080'));
