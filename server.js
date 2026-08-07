const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { getStreamingResponse } = require('./services/aiProvider');
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

// ============================================
// MULTI-KEY ROTATION FOR GEMINI
// ============================================
const GEMINI_KEYS = [
  process.env.GEMINI_API_KEY,
  process.env.GEMINI_API_KEY_2
].filter(Boolean); // drops any that aren't set

let geminiKeyIndex = 0;

function getNextGeminiKey() {
  if (GEMINI_KEYS.length === 0) return null;
  const key = GEMINI_KEYS[geminiKeyIndex % GEMINI_KEYS.length];
  geminiKeyIndex++;
  return key;
}

// Keep the existing API_KEYS object for other providers, but for gemini
// we'll pull from getNextGeminiKey() at call time instead of a fixed value.
const API_KEYS = {
  openai: process.env.OPENAI_API_KEY,
  gemini: null, // resolved per-request via getNextGeminiKey()
  bigmodel: process.env.BIGMODEL_API_KEY,
  deepseek: process.env.DEEPSEEK_API_KEY,
  groq: process.env.GROQ_API_KEY,
};

// ---- Defensive helper: strip any "data:image/...;base64," prefix from a base64 string ----
// Some older frontend code paths may still send the full data URL prefix. Providers
// expect clean base64, so strip it defensively before sending to any vision model.
function stripDataUrlPrefix(base64) {
  if (typeof base64 !== 'string') return base64;
  const commaIndex = base64.indexOf(',');
  return base64.startsWith('data:') && commaIndex !== -1
    ? base64.slice(commaIndex + 1)
    : base64;
}

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
Reply with ONLY a valid JSON object and nothing else — no explanations, no markdown, no code fences, no text before or after. The entire response must be exactly one of these two forms:
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

    // Groq sometimes returns non-JSON text (e.g. "I cannot...") instead of the
    // expected {"remember": ...} object. Parse defensively and return null
    // silently on failure — this is a background best-effort feature, so a
    // parse failure is not an error worth logging every time.
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (parseErr) {
      return null;
    }
    if (parsed && parsed.remember && parsed.fact) {
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
// CHAT STORAGE (per-user, Redis-backed)
// ============================================
// chat:<username>:<chatId>   -> JSON string of the full chat object
// user_chat_ids:<username>   -> Redis Set of this user's chat IDs

function chatKey(username, chatId) {
  return `chat:${username}:${chatId}`;
}
function userChatIdsKey(username) {
  return `user_chat_ids:${username}`;
}

// ---- List all chats for a user (summaries only, for the sidebar) ----
app.get('/api/chats', requireAuth, async (req, res) => {
  try {
    const chatIds = await redisCommand(['SMEMBERS', userChatIdsKey(req.username)]);
    if (!chatIds || chatIds.length === 0) {
      return res.json({ success: true, chats: [] });
    }

    // Fetch all chats in parallel
    const chatStrings = await Promise.all(
      chatIds.map(id => redisCommand(['GET', chatKey(req.username, id)]))
    );

    const summaries = chatStrings
      .filter(Boolean)
      .map(str => {
        const chat = JSON.parse(str);
        return {
          id: chat.id,
          title: chat.title || 'New Chat',
          updatedAt: chat.updatedAt || chat.createdAt || 0
        };
      })
      .sort((a, b) => b.updatedAt - a.updatedAt); // most recent first

    res.json({ success: true, chats: summaries });
  } catch (err) {
    console.error('List chats failed:', err.message);
    res.status(500).json({ success: false, error: 'Failed to load chats' });
  }
});

// ---- Get one full chat (with all messages) ----
app.get('/api/chats/:chatId', requireAuth, async (req, res) => {
  try {
    const raw = await redisCommand(['GET', chatKey(req.username, req.params.chatId)]);
    if (!raw) return res.status(404).json({ success: false, error: 'Chat not found' });
    res.json({ success: true, chat: JSON.parse(raw) });
  } catch (err) {
    console.error('Get chat failed:', err.message);
    res.status(500).json({ success: false, error: 'Failed to load chat' });
  }
});

// ---- Save/update a chat (full object: id, title, messages, timestamps) ----
app.post('/api/chats/:chatId', requireAuth, async (req, res) => {
  try {
    const chatId = req.params.chatId;
    const chat = req.body.chat;
    if (!chat) return res.status(400).json({ success: false, error: 'Missing chat data' });

    chat.id = chatId;
    chat.updatedAt = Date.now();
    if (!chat.createdAt) chat.createdAt = chat.updatedAt;

    await redisCommand(['SET', chatKey(req.username, chatId), JSON.stringify(chat)]);
    await redisCommand(['SADD', userChatIdsKey(req.username), chatId]);

    res.json({ success: true });
  } catch (err) {
    console.error('Save chat failed:', err.message);
    res.status(500).json({ success: false, error: 'Failed to save chat' });
  }
});

// ---- Delete a chat ----
app.delete('/api/chats/:chatId', requireAuth, async (req, res) => {
  try {
    const chatId = req.params.chatId;
    await redisCommand(['DEL', chatKey(req.username, chatId)]);
    await redisCommand(['SREM', userChatIdsKey(req.username), chatId]);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete chat failed:', err.message);
    res.status(500).json({ success: false, error: 'Failed to delete chat' });
  }
});

// ---- Delete ALL chats for a user ("Clear all chat history") ----
app.delete('/api/chats', requireAuth, async (req, res) => {
  try {
    const chatIds = await redisCommand(['SMEMBERS', userChatIdsKey(req.username)]);
    if (chatIds && chatIds.length > 0) {
      await Promise.all(chatIds.map(id => redisCommand(['DEL', chatKey(req.username, id)])));
    }
    await redisCommand(['DEL', userChatIdsKey(req.username)]);
    res.json({ success: true });
  } catch (err) {
    console.error('Clear all chats failed:', err.message);
    res.status(500).json({ success: false, error: 'Failed to clear chats' });
  }
});

// ============================================
// HELPER: try a provider, return { ok, response, apiKeyUsed }
// ============================================

async function tryProvider(provider, model, messages, imageBase64, imageMimeType, pdfText) {
  let apiKey;

  if (provider === 'gemini') {
    apiKey = getNextGeminiKey();
    if (!apiKey) return { ok: false, status: 500, errText: 'No Gemini key configured' };
  } else {
    apiKey = API_KEYS[provider];
    if (!apiKey) return { ok: false, status: 500, errText: `API key for ${provider} not configured` };
  }

  let response;
   try {
     if (provider === 'gemini') {
       response = await handleGemini(model, apiKey, messages, imageBase64, imageMimeType, pdfText);
    } else {
      response = await handleOpenAICompatible(provider, model, apiKey, messages, imageBase64, imageMimeType, pdfText);
    }
  } catch (err) {
    return { ok: false, status: 500, errText: err.message };
  }

  if (!response.ok) {
    const errText = await response.text();
    return { ok: false, status: response.status, errText };
  }

  console.log('Used provider:', provider, provider === 'gemini' ? `(gemini key index ${geminiKeyIndex - 1})` : '');
  return { ok: true, response };
}

// ============================================
// FALLBACK CHAIN when a provider fails with quota/model errors
// ============================================

// Maps each provider to a sensible default model to use as a fallback
const FALLBACK_MODEL_MAP = {
  gemini: 'gemini-flash-latest',
  groq: 'llama-3.3-70b-versatile',
  bigmodel: 'glm-4-flash',
};

const FALLBACK_ORDER = ['gemini', 'groq', 'bigmodel'];

function isRetryableError(status) {
  return status === 429 || status === 404 || status === 503;
}

async function callWithFallback(originalProvider, originalModel, messages, imageBase64, imageMimeType, pdfText) {
  // Try the user's originally selected provider first
  let result = await tryProvider(originalProvider, originalModel, messages, imageBase64, imageMimeType, pdfText);
  if (result.ok) return result;

  if (!isRetryableError(result.status)) {
    // Not a quota/availability issue (e.g. bad request) — don't waste calls retrying elsewhere
    return result;
  }

  console.log(`Provider ${originalProvider} failed (status ${result.status}), trying fallback chain...`);

  // Try each fallback provider in order, skipping the one that already failed
  for (const provider of FALLBACK_ORDER) {
    if (provider === originalProvider) continue;
    if (!API_KEYS[provider] && provider !== 'gemini') continue; // skip unconfigured providers
    if (provider === 'gemini' && GEMINI_KEYS.length === 0) continue;

    const fallbackModel = FALLBACK_MODEL_MAP[provider];
    console.log(`Trying fallback provider: ${provider} (${fallbackModel})`);

    result = await tryProvider(provider, fallbackModel, messages, imageBase64, imageMimeType, pdfText);
    if (result.ok) return result;

    if (!isRetryableError(result.status)) {
      // This fallback failed for a different reason — stop trying further fallbacks
      return result;
    }
  }

  // Everything failed
  return result;
}

// ============================================
// AI CHAT ROUTE (auth required, per-user memory + webSearch support)
// ============================================
app.post('/chat', requireAuth, async (req, res) => {
  const { provider, model, messages, imageBase64, imageMimeType, pdfText, webSearch } = req.body;

  if (!provider || !model || !messages) {
    return res.status(400).json({ error: 'Missing provider, model, or messages' });
  }

  let finalMessages = messages;
  let sources = [];

  // ---- Build a single combined system message (grounding + memory + web search) ----
  const systemParts = [];

  // NEW: Always include this grounding instruction FIRST — it explicitly tells the
  // model to treat the conversation history (including its own earlier responses,
  // such as descriptions or transcriptions of any images or documents the user
  // shared) as reliable ground truth, and to answer confidently about earlier
  // topics instead of saying it doesn't have access.
  systemParts.push(
    `This is an ongoing conversation. Everything in the message history below — ` +
    `including your own earlier responses (such as descriptions or transcriptions ` +
    `of any images or documents the user shared) — is real, accurate context from ` +
    `this same conversation. Treat it as ground truth. If the user refers back to ` +
    `something discussed earlier (a problem, an image, a document, a fact), answer ` +
    `confidently using that prior context — do not say you don't have access to it ` +
    `or aren't sure, since it is right here in the conversation history.`
  );

  // Inject this user's saved memory
  const memoryFacts = await getMemory(req.username);
  console.log('Memory fetched for', req.username, ':', memoryFacts);
  if (memoryFacts.length > 0) {
    systemParts.push(`You know the following facts about this user from previous conversations. Treat these as true and answer questions about the user directly and confidently using this information — do not say you don't know or don't have access to past conversations:\n${memoryFacts.map(f => `- ${f}`).join('\n')}`);
  }

  // Web search injection
  if (webSearch) {
    try {
      const lastUserMsg = [...messages].reverse().find(m => m.role === 'user');
      const query = lastUserMsg ? lastUserMsg.content : '';

      const results = await searchWeb(query);
      sources = results.map(r => ({ title: r.title, link: r.url }));

      const context = results
        .map((r, i) => `[${i + 1}] ${r.title}\n${r.content}\nSource: ${r.url}`)
        .join('\n\n');

      systemParts.push(`You have access to the following up-to-date web search results. Use them to answer the user's question accurately. Cite sources using [1], [2] etc. where relevant. If not relevant, answer using your own knowledge instead.\n\nWeb Search Results:\n${context}`);
    } catch (err) {
      console.error('Web search failed, proceeding without it:', err.message);
    }
  }

  if (systemParts.length > 0) {
    finalMessages = [{ role: 'system', content: systemParts.join('\n\n---\n\n') }, ...messages];
  }

  // ---- Background: extract & save new memory fact for this user ----
  const lastUserMsg = [...messages].reverse().find(m => m.role === 'user');
  if (lastUserMsg && typeof lastUserMsg.content === 'string') {
    extractMemoryFact(lastUserMsg.content).then(fact => {
      if (fact) addMemory(req.username, fact);
    });
  }

  // ---- Call with automatic fallback chain ----
  try {
    const { response: providerResponse } = await getStreamingResponse(
      provider, model, finalMessages, imageBase64, imageMimeType, pdfText
    );

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Search-Sources', encodeURIComponent(JSON.stringify(sources)));

    const reader = providerResponse.body;
    reader.on('data', (chunk) => res.write(chunk));
    reader.on('end', () => res.end());
    reader.on('error', () => res.end());

  } catch (error) {
    console.error('Chat error (all providers failed):', error.message);
    res.status(500).json({ error: 'All AI providers are currently unavailable. Please try again shortly.' });
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
        const cleanBase64 = stripDataUrlPrefix(imageBase64);
        parts.push({
          inlineData: {
            mimeType: imageMimeType || 'image/jpeg',
            data: cleanBase64
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
          const cleanBase64 = stripDataUrlPrefix(imageBase64);
          processedMessages.push({
            role: 'user',
            content: [
              { type: 'text', text: content },
              {
                type: 'image_url',
                image_url: {
                  url: `data:${imageMimeType || 'image/jpeg'};base64,${cleanBase64}`,
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
  const configuredProviders = Object.keys(API_KEYS).filter(k => API_KEYS[k]);
  if (GEMINI_KEYS.length > 0) configuredProviders.push('gemini');
  console.log('Configured providers:', configuredProviders.join(', ') || 'NONE');
  console.log(`Gemini keys configured: ${GEMINI_KEYS.length} (rotation enabled)`);
});
