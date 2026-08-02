const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

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

app.use(express.json({ limit: '50mb' }));

const API_KEYS = {
  openai: process.env.OPENAI_API_KEY,
  gemini: process.env.GEMINI_API_KEY,
  bigmodel: process.env.BIGMODEL_API_KEY,
  deepseek: process.env.DEEPSEEK_API_KEY,
  groq: process.env.GROQ_API_KEY,
};

// ============================================
// AUTH SYSTEM (username + password, no email)
// ============================================
const JWT_SECRET = process.env.JWT_SECRET; // set this in Render env vars (any long random string)

// ---- User storage in Redis ----
// Each user stored as a Redis hash: user:<username> -> { passwordHash }
// Memory stored per-user: user_memory:<username> -> list of facts

async function getUser(username) {
  const result = await redisCommand(['HGETALL', `user:${username}`]);
  if (!result || result.length === 0) return null;
  // result comes back as a flat array [field1, value1, field2, value2, ...]
  const obj = {};
  for (let i = 0; i < result.length; i += 2) {
    obj[result[i]] = result[i + 1];
  }
  return obj;
}

async function createUser(username, passwordHash) {
  await redisCommand(['HSET', `user:${username}`, 'passwordHash', passwordHash]);
}

// ---- Signup route ----
app.post('/auth/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  if (username.length < 3 || password.length < 6) {
    return res.status(400).json({ error: 'Username must be 3+ chars, password 6+ chars' });
  }

  const cleanUsername = username.trim().toLowerCase();

  const existing = await getUser(cleanUsername);
  if (existing) {
    return res.status(409).json({ error: 'Username already taken' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await createUser(cleanUsername, passwordHash);

  const token = jwt.sign({ username: cleanUsername }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ success: true, token, username: cleanUsername });
});

// ---- Login route ----
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const cleanUsername = username.trim().toLowerCase();
  const user = await getUser(cleanUsername);

  if (!user || !user.passwordHash) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const token = jwt.sign({ username: cleanUsername }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ success: true, token, username: cleanUsername });
});

// ---- Middleware: verify JWT on protected routes ----
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Authenticated as:', decoded.username);
    req.username = decoded.username;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

// ============================================
// MEMORY SYSTEM using Upstash Redis
// ============================================
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const MEMORY_KEY = 'user_memory'; // single-user app, so one global key is fine

// ---- Low-level Redis REST helpers ----

async function redisCommand(commandArray) {
  const response = await fetch(UPSTASH_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${UPSTASH_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(commandArray)
  });
  const data = await response.json();
  return data.result;
}

// Get all saved memory facts for a user (returns array of strings)
async function getMemory(username) {
  try {
    const result = await redisCommand(['LRANGE', `user_memory:${username}`, '0', '-1']);
    return result || [];
  } catch (err) {
    console.error('Memory fetch failed:', err.message);
    return [];
  }
}

// Add a new memory fact for a user
async function addMemory(username, fact) {
  try {
    await redisCommand(['RPUSH', `user_memory:${username}`, fact]);
    // Keep only the most recent 200 facts to avoid unbounded growth
    await redisCommand(['LTRIM', `user_memory:${username}`, '-200', '-1']);
  } catch (err) {
    console.error('Memory save failed:', err.message);
  }
}

// Delete all memory for a user (for a "forget everything" feature)
async function clearMemory(username) {
  try {
    await redisCommand(['DEL', `user_memory:${username}`]);
  } catch (err) {
    console.error('Memory clear failed:', err.message);
  }
}

// ---- Lightweight fact-extraction using Groq (fast + free) ----

async function extractMemoryFact(userMessage) {
  if (!process.env.GROQ_API_KEY) return null;

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'llama-3.1-8b-instant',
        messages: [
          {
            role: 'system',
            content: `You extract durable personal facts worth remembering long-term from a user's message (name, location, preferences, job, ongoing projects, etc). 
Reply with ONLY a JSON object, nothing else:
{"remember": true, "fact": "short factual sentence"} if there's something worth saving,
or {"remember": false} if not (e.g. for greetings, questions, small talk).
Do not save temporary/one-off info (like "what's the weather today").`
          },
          { role: 'user', content: userMessage }
        ],
        max_tokens: 100,
        temperature: 0
      })
    });

    const data = await response.json();
    const text = data.choices?.[0]?.message?.content?.trim();
    if (!text) return null;

    const parsed = JSON.parse(text);
    if (parsed.remember && parsed.fact) {
      return parsed.fact;
    }
    return null;
  } catch (err) {
    console.error('Memory extraction failed:', err.message);
    return null;
  }
}

// Vision-capable models
const VISION_MODELS = {
  openai: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo'],
  gemini: ['gemini-flash-latest', 'gemini-2.5-pro', 'gemini-2.0-flash'],
  bigmodel: ['glm-4v', 'glm-4v-plus'],
};

function supportsVision(provider, model) {
  const models = VISION_MODELS[provider];
  return models ? models.some(m => model.toLowerCase() === m.toLowerCase()) : false;
}

// Health check
app.get('/', (req, res) => {
  res.json({ message: 'Multi-AI Chat Backend is running!', status: 'Multi-AI Proxy Server is running', version: '3.0.0', features: ['chat', 'image-analysis', 'pdf-analysis', 'search'] });
});

// ============================================
// TAVILY SEARCH API
// ============================================
async function searchTavily(query) {
  const response = await fetch('https://api.tavily.com/search', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      api_key: process.env.TAVILY_API_KEY,
      query: query,
      search_depth: 'basic',
      max_results: 5
    })
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || 'Search failed');
  }

  return data.results; // array of {title, url, content, ...}
}

// ============================================
// SERPER SEARCH API (fallback for Tavily)
// ============================================
async function searchSerper(query) {
  const response = await fetch('https://google.serper.dev/search', {
    method: 'POST',
    headers: {
      'X-API-KEY': process.env.SERPER_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ q: query })
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.message || 'Serper search failed');
  }

  // Normalize Serper's organic results to match Tavily's format
  const organic = data.organic || [];
  return organic.slice(0, 5).map(item => ({
    title: item.title,
    url: item.link,
    content: item.snippet
  }));
}

// ============================================
// COMBINED SEARCH WITH FALLBACK
// ============================================
async function searchWeb(query) {
  try {
    return await searchTavily(query);
  } catch (err) {
    console.error('Tavily failed, falling back to Serper:', err.message);
    try {
      return await searchSerper(query);
    } catch (err2) {
      console.error('Serper also failed:', err2.message);
      throw new Error('Both search providers failed');
    }
  }
}

app.get('/api/search', async (req, res) => {
  const query = req.query.q;
  
  if (!query) {
    return res.status(400).json({ 
      error: 'Query parameter "q" is required' 
    });
  }

  try {
    const results = await searchWeb(query);

    // Map search results to frontend format
    const mappedResults = results.map(item => ({
      title: item.title,
      link: item.url,
      snippet: item.content
    }));

    res.json({ 
      success: true,
      query: query,
      results: mappedResults 
    });

  } catch (error) {
    console.error('Search error:', error.message);
    res.status(500).json({ 
      success: false,
      error: 'Search failed',
      details: error.message
    });
  }
});

// ============================================
// MEMORY ROUTES: view / clear memory (auth required, per-user)
// ============================================
app.get('/api/memory', requireAuth, async (req, res) => {
  const facts = await getMemory(req.username);
  res.json({ success: true, facts });
});

app.delete('/api/memory', requireAuth, async (req, res) => {
  await clearMemory(req.username);
  res.json({ success: true });
});

// ============================================
// AI CHAT ROUTE (auth required, per-user memory + webSearch support)
// ============================================
app.post('/chat', requireAuth, async (req, res) => {
  const { provider, model, messages, imageBase64, imageMimeType, pdfText, webSearch } = req.body;

  if (!provider || !model || !messages) {
    return res.status(400).json({ error: 'Missing provider, model, or messages' });
  }

  const apiKey = API_KEYS[provider];
  if (!apiKey) {
    return res.status(500).json({ error: `API key for ${provider} not configured on server` });
  }

  let finalMessages = messages;
  let sources = [];

  // ---- Inject this user's saved memory ----
  const memoryFacts = await getMemory(req.username);
  console.log('Memory fetched for', req.username, ':', memoryFacts);
  if (memoryFacts.length > 0) {
    const memoryContext = {
      role: 'system',
      content: `Here is what you remember about this user from past conversations:\n${memoryFacts.map(f => `- ${f}`).join('\n')}\n\nUse this naturally when relevant, without explicitly saying "according to my memory" unless asked.`
    };
    finalMessages = [memoryContext, ...finalMessages];
  }

  // ---- Web search injection (existing logic) ----
  if (webSearch) {
    try {
      const lastUserMsg = [...messages].reverse().find(m => m.role === 'user');
      const query = lastUserMsg ? lastUserMsg.content : '';

      const results = await searchWeb(query);
      sources = results.map(r => ({ title: r.title, link: r.url }));

      const context = results
        .map((r, i) => `[${i + 1}] ${r.title}\n${r.content}\nSource: ${r.url}`)
        .join('\n\n');

      const searchSystemMsg = {
        role: 'system',
        content: `You have access to the following up-to-date web search results. Use them to answer the user's question accurately. Cite sources using [1], [2] etc. where relevant. If not relevant, answer using your own knowledge instead.\n\nWeb Search Results:\n${context}`
      };

      finalMessages.splice(finalMessages.length - 1, 0, searchSystemMsg);
    } catch (err) {
      console.error('Web search failed, proceeding without it:', err.message);
    }
  }

  // ---- Background: extract & save new memory fact for this user ----
  const lastUserMsg = [...messages].reverse().find(m => m.role === 'user');
  if (lastUserMsg && typeof lastUserMsg.content === 'string') {
    extractMemoryFact(lastUserMsg.content).then(fact => {
      if (fact) addMemory(req.username, fact);
    });
  }

  try {
    let response;

    if (provider === 'gemini') {
      response = await handleGemini(model, apiKey, finalMessages, imageBase64, imageMimeType, pdfText);
    } else {
      response = await handleOpenAICompatible(provider, model, apiKey, finalMessages, imageBase64, imageMimeType, pdfText);
    }

    if (!response.ok) {
      const errText = await response.text();
      return res.status(response.status).json({ error: errText });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    // Send sources as a custom header before streaming starts (frontend can read this)
    res.setHeader('X-Search-Sources', encodeURIComponent(JSON.stringify(sources)));

    const reader = response.body;
    reader.on('data', (chunk) => res.write(chunk));
    reader.on('end', () => res.end());
    reader.on('error', () => res.end());

  } catch (error) {
    console.error('Proxy error:', error);
    res.status(500).json({ error: error.message });
  }
});

async function handleGemini(model, apiKey, messages, imageBase64, imageMimeType, pdfText) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${apiKey}`;

  const contents = [];
  let systemInstruction = null;

  // Separate system message
  for (const msg of messages) {
    if (msg.role === 'system') {
      systemInstruction = { parts: [{ text: msg.content }] };
      continue;
    }

    const parts = [];

    if (msg.role === 'user') {
      // Add PDF text if this is the last user message and PDF is attached
      const isLastUser = messages.filter(m => m.role === 'user').pop() === msg;
      if (isLastUser && pdfText) {
        parts.push({ text: `[PDF Content]:\n${pdfText}\n\n[User Question]:\n${msg.content}` });
      } else {
        parts.push({ text: msg.content });
      }

      // Add image if this is the last user message and image is attached
      if (isLastUser && imageBase64) {
        parts.push({
          inlineData: {
            mimeType: imageMimeType || 'image/jpeg',
            data: imageBase64
          }
        });
      }
    } else {
      parts.push({ text: msg.content });
    }

    contents.push({
      role: msg.role === 'user' ? 'user' : 'model',
      parts
    });
  }

  const body = { contents };
  if (systemInstruction) {
    body.systemInstruction = systemInstruction;
  }

  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
}

async function handleOpenAICompatible(provider, model, apiKey, messages, imageBase64, imageMimeType, pdfText) {
  let url;

  if (provider === 'openai') {
    url = 'https://api.openai.com/v1/chat/completions';
  } else if (provider === 'bigmodel') {
    url = 'https://open.bigmodel.cn/api/paas/v4/chat/completions';
  } else if (provider === 'deepseek') {
    url = 'https://api.deepseek.com/chat/completions';
  } else if (provider === 'groq') {
    url = 'https://api.groq.com/openai/v1/chat/completions';
  }

  const headers = {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json'
  };

  const processedMessages = [];

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];

    if (msg.role === 'system') {
      processedMessages.push(msg);
      continue;
    }

    if (msg.role === 'user') {
      const isLastUser = messages.filter(m => m.role === 'user').pop() === msg;
      let content = msg.content;

      // Prepend PDF text
      if (isLastUser && pdfText) {
        content = `[PDF Content]:\n${pdfText}\n\n[User Question]:\n${content}`;
      }

      // Handle image attachment
      if (isLastUser && imageBase64) {
        if (supportsVision(provider, model)) {
          // Use vision format
          processedMessages.push({
            role: 'user',
            content: [
              { type: 'text', text: content },
              {
                type: 'image_url',
                image_url: {
                  url: `data:${imageMimeType || 'image/jpeg'};base64,${imageBase64}`,
                  detail: 'high'
                }
              }
            ]
          });
          continue;
        } else {
          // Model doesn't support vision - add note
          content = `[Note: The user has uploaded an image, but this AI model does not support image input. I can only analyze the text content.]\n\n${content}`;
        }
      }

      processedMessages.push({ role: 'user', content });
    } else {
      processedMessages.push(msg);
    }
  }

  return fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      messages: processedMessages,
      stream: true,
      max_tokens: 4096
    })
  });
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('🚀 Multi-AI Proxy Server running on port', PORT);
  console.log('Configured providers:', Object.keys(API_KEYS).filter(k => API_KEYS[k]).join(', ') || 'NONE');
});