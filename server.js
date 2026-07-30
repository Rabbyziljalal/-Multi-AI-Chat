const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();

// Allow your GitHub Pages frontend
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://rabbyziljalal.github.io';
app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (origin.startsWith(ALLOWED_ORIGIN) || origin === 'http://localhost:3000' || origin === 'http://127.0.0.1:5500') {
      return callback(null, true);
    }
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

app.use(express.json());

const API_KEYS = {
  openai: process.env.OPENAI_API_KEY,
  gemini: process.env.GEMINI_API_KEY,
  bigmodel: process.env.BIGMODEL_API_KEY,
  deepseek: process.env.DEEPSEEK_API_KEY,
  groq: process.env.GROQ_API_KEY,
};

const PROVIDERS = {
  openai: {
    baseUrl: 'https://api.openai.com/v1/chat/completions',
    headers: (key) => ({ 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' }),
    body: (messages, model) => ({ model, messages, stream: true }),
  },
  gemini: {
    baseUrl: (model, key) => `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${key}`,
    headers: () => ({ 'Content-Type': 'application/json' }),
    body: (messages) => ({
      contents: messages.map(m => ({
        role: m.role === 'user' ? 'user' : 'model',
        parts: [{ text: m.content }]
      }))
    }),
  },
  bigmodel: {
    baseUrl: 'https://open.bigmodel.cn/api/paas/v4/chat/completions',
    headers: (key) => ({ 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' }),
    body: (messages, model) => ({ model, messages, stream: true }),
  },
  deepseek: {
    baseUrl: 'https://api.deepseek.com/chat/completions',
    headers: (key) => ({ 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' }),
    body: (messages, model) => ({ model, messages, stream: true }),
  },
  groq: {
    baseUrl: 'https://api.groq.com/openai/v1/chat/completions',
    headers: (key) => ({ 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' }),
    body: (messages, model) => ({ model, messages, stream: true }),
  },
};

app.get('/', (req, res) => {
  res.json({ status: 'Multi-AI Proxy Server is running', version: '1.0.0' });
});

app.post('/chat', async (req, res) => {
  const { provider, model, messages } = req.body;
  if (!provider || !model || !messages) {
    return res.status(400).json({ error: 'Missing provider, model, or messages' });
  }
  
  const apiKey = API_KEYS[provider];
  if (!apiKey) {
    return res.status(500).json({ error: `API key for ${provider} not configured on server` });
  }
  
  const config = PROVIDERS[provider];
  const url = typeof config.baseUrl === 'function' ? config.baseUrl(model, apiKey) : config.baseUrl;
  const headers = config.headers(apiKey);
  const body = config.body(messages, model);
  
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    
    if (!response.ok) {
      const errText = await response.text();
      return res.status(response.status).json({ error: errText });
    }
    
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    
    const reader = response.body;
    reader.on('data', (chunk) => res.write(chunk));
    reader.on('end', () => res.end());
    reader.on('error', () => res.end());
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Multi-AI Proxy Server running on port ${PORT}`);
});