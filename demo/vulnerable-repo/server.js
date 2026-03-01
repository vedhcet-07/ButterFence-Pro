const { exec } = require('child_process');
const express = require('express');
const app = express();

// Dangerous: eval on user input
app.get('/calc', (req, res) => {
  const result = eval(req.query.expression);
  res.json({ result });
});

// Dangerous: command injection
app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {
    res.send(stdout);
  });
});

// Hardcoded API key
const GOOGLE_API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv";

// Prototype pollution risk
app.post('/merge', (req, res) => {
  const obj = {};
  Object.assign(obj, req.body); // __proto__ pollution
  res.json(obj);
});

// Hardcoded Slack token
const SLACK_TOKEN = "xoxb-not-a-real-token-but-matches-pattern";

app.listen(3000);
