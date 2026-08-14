const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const FormData = require('form-data');
const { getStreamingResponse } = require('./services/aiProvider');
require('dotenv').config();

const app = express();

// ---- Fetch wrapper with a timeout ----
// If a provider doesn't respond within the window (default 20s), the request is
// aborted and throws — the caller treats that as a failure and moves on.
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(function() { controller.abort(); }, timeoutMs || 20000);
  try {
    const response = await fetch(url, Object.assign({}, options, { signal: controller.signal }));
    clearTimeout(timeout);
    return response;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

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
  openrouter: process.env.OPENROUTER_API_KEY,   // NEW
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

// ============================================================
// AUTH SYSTEM (username + email + password signup, email + password login)
//
// Key change: signup now takes THREE fields (username, email,
// password). Email is the unique account identifier (what's stored
// in Redis, what JWT is signed with, what all existing per-user
// scoping — chat:<x>, user_memory:<x> — continues to use, exactly
// as before, just now guaranteed to be a real email since it's a
// separate validated field). Username is a separate display-name
// field, returned to the frontend and used for the "Welcome, X"
// heading, editable later in Settings exactly as before.
//
// Login now takes EMAIL + password only (no username field).
// ============================================================
const JWT_SECRET = process.env.JWT_SECRET; // set this in Render env vars (any long random string)

// ---- User storage in Redis — keyed by EMAIL (unique identifier) ----
// user:<email> -> { username, passwordHash }

async function getUser(email) {
  const result = await redisCommand(['HGETALL', `user:${email}`]);
  if (!result || result.length === 0) return null;
  const obj = {};
  for (let i = 0; i < result.length; i += 2) {
    obj[result[i]] = result[i + 1];
  }
  return obj;
}

async function createUser(email, username, passwordHash) {
  await redisCommand(['HSET', `user:${email}`, 'username', username, 'passwordHash', passwordHash]);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ---- Signup route: username + email + password ----
app.post('/auth/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are all required' });
  }
  if (username.trim().length < 2) {
    return res.status(400).json({ error: 'Username must be at least 2 characters' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanUsername = username.trim();

  const existing = await getUser(cleanEmail);
  if (existing) {
    return res.status(409).json({ error: 'An account with this email already exists' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await createUser(cleanEmail, cleanUsername, passwordHash);

  const token = jwt.sign({ email: cleanEmail }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ success: true, token, email: cleanEmail, username: cleanUsername });
});

// ---- Login route: email + password only ----
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const user = await getUser(cleanEmail);

  if (!user || !user.passwordHash) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign({ email: cleanEmail }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ success: true, token, email: cleanEmail, username: user.username || cleanEmail });
});

// ---- requireAuth middleware — unchanged in structure, just signs/reads `email` now ----
// (req.username continues to be used as the scoping identifier everywhere else in
// the app — chat storage, memory, etc. — exactly as before. We keep the variable
// name req.username for zero disruption to all that existing code, but its value
// is now guaranteed to be a validated email address.)
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Authenticated as:', decoded.email);
    req.username = decoded.email; // unchanged variable name — all existing scoping logic keeps working as-is
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

// ---- Permanent account deletion: removes ALL chats, memory, and the account record ----
app.delete('/auth/account', requireAuth, async (req, res) => {
  const email = req.username; // scoping identifier, now guaranteed to be the email

  try {
    // 1) Delete all chats and the chat-id index
    const chatIds = await redisCommand(['SMEMBERS', userChatIdsKey(email)]);
    if (chatIds && chatIds.length > 0) {
      await Promise.all(chatIds.map(id => redisCommand(['DEL', chatKey(email, id)])));
    }
    await redisCommand(['DEL', userChatIdsKey(email)]);

    // 2) Delete memory
    await redisCommand(['DEL', `user_memory:${email}`]);

    // 3) Delete the user account record itself (email/username/passwordHash)
    await redisCommand(['DEL', `user:${email}`]);

    console.log('Account permanently deleted:', email);
    res.json({ success: true });
  } catch (err) {
    console.error('Account deletion failed:', err.message);
    res.status(500).json({ success: false, error: 'Failed to delete account' });
  }
});

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

IMPORTANT: Only save facts that are directly about the USER THEMSELVES (first-person statements like "I am...", "my...", "I like...", "I work as..."). Do NOT save facts about other people the user merely mentions — for example, if the user says "my friend Ridoy plays cricket" or "Ridoy is from Bangladesh", that is information about Ridoy, not about the user, and must NOT be saved. Only extract something if it describes the user's own identity, preferences, situation, or life — not people, places, or things they simply talk about.

Reply with ONLY a JSON object, nothing else:
{"remember": true, "fact": "short factual sentence about the user"} if there's something worth saving about the USER,
or {"remember": false} if not (e.g. for greetings, questions, small talk, or facts about someone other than the user).
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

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      return null; // silently ignore non-JSON responses, as before
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

// ============================================================
// EXPLICIT MEMORY SAVE (guaranteed, bypasses the classifier)
// ============================================================
// Detects explicit "remember this" / "save this to memory" style requests and
// saves them IMMEDIATELY and GUARANTEED — bypassing the probabilistic Groq
// classifier used for automatic/implicit extraction, which can sometimes
// decide not to save something even when it should.
//
// Note: memory is already scoped per-USER (not per-chat), so anything saved
// here is automatically available in every chat, not just the one it was
// saved from. No change needed for that part — it already works via
// getMemory(req.username) in the /chat route.

// ============================================================
// Root cause of the bug: the previous list only covered English
// phrasing and Bangla SCRIPT (মনে রাখো), but missed Romanized
// Bangla / "Banglish" phrasing (e.g. "save kore rakho memory te",
// "mone rakho"), which is how this user actually types most of the
// time. That's why the explicit save wasn't detected.
// ============================================================
const EXPLICIT_MEMORY_TRIGGERS = [
  // English
  /remember (that|this)/i,
  /save (this|that) to (your )?memory/i,
  /please remember/i,
  /keep this in mind/i,
  /don'?t forget/i,
  // Bangla script
  /মনে রাখো/,
  /মনে রেখো/,
  /মনে রাখবে/,
  /সেভ কর/,
  /মেমোরিতে রাখো/,
  // Romanized Bangla / Banglish — covers how many Bangla speakers
  // actually type on a chat app, using English letters
  /mone rak/i,        // covers "mone rakho", "mone rakbe", "mone rakhbo"
  /mone rekho/i,
  /save kore rakho/i,
  /save kore rakh/i,
  /memory te rakho/i,
  /memory te rakh/i,
  /memory te save/i,
  /save.*memory/i,     // catches "ata save kore rakho memory te" style ordering
  /mone thakuk/i,
  /bhule jeo na/i,      // "don't forget" in Banglish
  /মনে রাখিস/           // informal spelling variant (mixed script safety net)
];

function detectExplicitMemoryRequest(text) {
  if (typeof text !== 'string') return false;
  return EXPLICIT_MEMORY_TRIGGERS.some(pattern => pattern.test(text));
}

// Extract the actual fact when an explicit trigger is detected.
// Unlike extractMemoryFact() (which asks Groq "should I remember this, yes/no"),
// this version SKIPS the yes/no decision — the user already explicitly asked to
// remember it, so we only ask Groq to help phrase it cleanly as a fact. If Groq
// is unavailable or fails, fall back to saving the raw message text directly
// rather than losing it.
async function extractExplicitMemoryFact(userMessage) {
  if (!process.env.GROQ_API_KEY) {
    return userMessage.trim(); // no Groq available — save raw text as a safe fallback
  }

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
            content: `The user explicitly asked you to remember something. Rewrite what they want remembered as a single short, clear factual sentence, removing phrases like "remember that" or "please save this". Reply with ONLY the rewritten sentence, nothing else — no quotes, no JSON, no explanation.`
          },
          { role: 'user', content: userMessage }
        ],
        max_tokens: 100,
        temperature: 0
      })
    });

    const data = await response.json();
    const text = data.choices?.[0]?.message?.content?.trim();
    return text || userMessage.trim(); // fallback to raw text if Groq gives nothing usable
  } catch (err) {
    console.error('Explicit memory extraction failed, saving raw text instead:', err.message);
    return userMessage.trim(); // never silently lose an explicit save request
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

// ---- Serper call helper with multi-key fallback ----
// Tries SERPER_API_KEY first, then SERPER_API_KEY_1 if the first fails.
// Axios throws on non-2xx, so the returned value is already parsed JSON.
async function callSerper(url, body) {
  const keys = [process.env.SERPER_API_KEY, process.env.SERPER_API_KEY_1].filter(Boolean);
  let lastError;
  for (const key of keys) {
    try {
      const response = await axios.post(url, body, {
        headers: { 'X-API-KEY': key, 'Content-Type': 'application/json' },
        timeout: 15000
      });
      console.log(`Serper request succeeded via key ending in ...${key.slice(-4)}`);
      return response.data;
    } catch (err) {
      console.log(`Serper key ending in ...${key.slice(-4)} failed:`, err.response ? err.response.status : err.message);
      lastError = err;
    }
  }
  throw lastError || new Error('No Serper API keys configured');
}

async function searchSerper(query) {
  const data = await callSerper('https://google.serper.dev/search', { q: query });

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
// VIDEO SEARCH API (Serper video search endpoint)
// ============================================
// Searches for YouTube videos via Serper's dedicated video search endpoint.
// Returns top 3-5 results with title, link, channel/source, and thumbnail.
app.post('/api/search-video', async (req, res) => {
  const { query } = req.body;

  if (!query || !query.trim()) {
    return res.status(400).json({ success: false, error: 'Query is required' });
  }

  try {
    if (!process.env.SERPER_API_KEY) {
      throw new Error('SERPER_API_KEY is not configured');
    }

    const data = await callSerper('https://google.serper.dev/videos', { q: query.trim() });
    const videos = (data.videos || []).slice(0, 5);

    if (videos.length === 0) {
      return res.json({ success: true, query: query.trim(), results: [] });
    }

    const results = videos.map(v => ({
      title: v.title || 'Untitled video',
      link: v.link || '#',
      channel: v.channel || v.source || 'Unknown channel',
      thumbnail: v.imageUrl || v.thumbnailUrl || null
    }));

    res.json({ success: true, query: query.trim(), results });

  } catch (error) {
    console.error('Video search error:', error.message);
    res.status(500).json({ success: false, error: 'Video search failed', details: error.message });
  }
});

// ============================================
// GENERIC SERPER SEARCH HELPER
// ============================================
// All Serper endpoints (news, shopping, places, maps, scholar, reviews,
// lens, webpage, autocomplete, patents) follow the exact same request
// pattern: POST to https://google.serper.dev/<endpoint> with { q: query }.
// This helper centralizes the fetch + error handling so each route below
// stays tiny and consistent with the existing /api/search-video pattern.
async function serperSearch(endpoint, query) {
  if (!process.env.SERPER_API_KEY) {
    throw new Error('SERPER_API_KEY is not configured');
  }

  return callSerper('https://google.serper.dev/' + endpoint, { q: query.trim() });
}

// ---- Generic route factory: builds a /api/search-<endpoint> route that
// calls serperSearch() and normalizes the response into { success, query, results }.
// Each endpoint's raw Serper response shape differs, so a normalizer function
// is passed in to map the raw data into a uniform array of result objects.
function createSerperSearchRoute(endpoint, normalizer) {
  return async (req, res) => {
    const { query } = req.body;

    if (!query || !query.trim()) {
      return res.status(400).json({ success: false, error: 'Query is required' });
    }

    try {
      const data = await serperSearch(endpoint, query.trim());
      const results = normalizer(data);

      res.json({ success: true, query: query.trim(), results });
    } catch (error) {
      console.error('Serper ' + endpoint + ' search error:', error.message);
      res.status(500).json({ success: false, error: endpoint + ' search failed', details: error.message });
    }
  };
}

// ============================================
// NEWS SEARCH API (Serper news endpoint)
// ============================================
app.post('/api/search-news', createSerperSearchRoute('news', function(data) {
  return (data.news || []).slice(0, 5).map(function(item) {
    return {
      title: item.title || 'Untitled',
      link: item.link || '#',
      snippet: item.snippet || '',
      source: item.source || '',
      date: item.date || '',
      thumbnail: item.imageUrl || null
    };
  });
}));

// ============================================
// SHOPPING SEARCH API (Serper shopping endpoint)
// ============================================
app.post('/api/search-shopping', createSerperSearchRoute('shopping', function(data) {
  return (data.shopping || []).slice(0, 5).map(function(item) {
    return {
      title: item.title || 'Untitled',
      link: item.link || '#',
      price: item.price || '',
      source: item.source || '',
      rating: item.rating || null,
      ratingCount: item.ratingCount || null,
      thumbnail: item.imageUrl || null
    };
  });
}));

// ============================================
// PLACES SEARCH API (Serper places endpoint)
// ============================================
app.post('/api/search-places', createSerperSearchRoute('places', function(data) {
  return (data.places || []).slice(0, 5).map(function(item) {
    return {
      title: item.title || 'Untitled',
      link: item.website || item.link || '#',
      address: item.address || '',
      rating: item.rating || null,
      ratingCount: item.ratingCount || null,
      phone: item.phone || '',
      thumbnail: item.thumbnailUrl || null
    };
  });
}));

// ============================================
// MAPS SEARCH API (Serper maps endpoint)
// ============================================
app.post('/api/search-maps', createSerperSearchRoute('maps', function(data) {
  return (data.places || []).slice(0, 5).map(function(item) {
    return {
      title: item.title || 'Untitled',
      link: item.website || item.link || '#',
      address: item.address || '',
      rating: item.rating || null,
      ratingCount: item.ratingCount || null,
      phone: item.phone || '',
      thumbnail: item.thumbnailUrl || null
    };
  });
}));

// ============================================
// SCHOLAR SEARCH API (Serper scholar endpoint)
// ============================================
app.post('/api/search-scholar', createSerperSearchRoute('scholar', function(data) {
  return (data.scholar || []).slice(0, 5).map(function(item) {
    return {
      title: item.title || 'Untitled',
      link: item.link || '#',
      snippet: item.snippet || '',
      publicationInfo: item.publicationInfo || '',
      publicationDate: item.publicationDate || '',
      authors: item.authors || '',
      pdfUrl: item.pdfUrl || null
    };
  });
}));

// ============================================
// REVIEWS SEARCH API (Serper reviews endpoint)
// ============================================
app.post('/api/search-reviews', createSerperSearchRoute('reviews', function(data) {
  return (data.reviews || []).slice(0, 5).map(function(item) {
    return {
      title: item.title || 'Untitled',
      link: item.link || '#',
      snippet: item.snippet || '',
      rating: item.rating || null,
      ratingCount: item.ratingCount || null,
      source: item.source || '',
      date: item.date || ''
    };
  });
}));

// ============================================
// LENS SEARCH API (Serper lens endpoint — image search)
// ============================================
// Serper's lens endpoint requires a PUBLICLY ACCESSIBLE image URL — it does
// NOT accept raw base64 image data (that causes a 400 error). So before
// calling Serper, we first upload the attached image to catbox.moe (free,
// no API key) to get a public URL, then pass that URL to Serper.
//
// Note: uploaded images on catbox.moe are public (anyone with the URL can
// view them) and persist indefinitely unless manually deleted.
async function uploadImageForLensSearch(base64Data, mimeType) {
  const buffer = Buffer.from(base64Data, 'base64');
  const extension = mimeType && mimeType.indexOf('png') !== -1 ? 'png' : 'jpg';

  const form = new FormData();
  form.append('reqtype', 'fileupload');
  form.append('fileToUpload', buffer, {
    filename: 'lens-search.' + extension,
    contentType: mimeType || 'image/jpeg'
  });

  const response = await fetch('https://catbox.moe/user/api.php', {
    method: 'POST',
    body: form,
    headers: form.getHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to upload image for lens search (status ' + response.status + ')');
  }

  const publicUrl = (await response.text()).trim();
  if (!publicUrl.startsWith('http')) {
    throw new Error('Image upload did not return a valid URL: ' + publicUrl);
  }

  return publicUrl;
}

app.post('/api/search-lens', async (req, res) => {
  const { query, image, imageUrl } = req.body;

  if (!query && !image && !imageUrl) {
    return res.status(400).json({ success: false, error: 'Query or image is required' });
  }

  try {
    if (!process.env.SERPER_API_KEY) {
      throw new Error('SERPER_API_KEY is not configured');
    }

    // Build the request body based on what was provided
    const body = {};
    if (image) {
      // Strip any data:image/...;base64, prefix if present (defensive)
      const commaIndex = image.indexOf(',');
      const cleanBase64 = image.startsWith('data:') && commaIndex !== -1
        ? image.slice(commaIndex + 1)
        : image;

      // Step 1: upload the image to catbox.moe to get a public URL
      const publicImageUrl = await uploadImageForLensSearch(cleanBase64, req.body.mimeType);
      console.log('Lens search — uploaded image to:', publicImageUrl);

      // Step 2: call Serper's Lens endpoint with that public URL
      body.url = publicImageUrl;
    } else if (imageUrl) {
      body.url = imageUrl;
    } else {
      body.q = query.trim();
    }

    const data = await callSerper('https://google.serper.dev/lens', body);

    // Defensive extraction: try the most likely field names in order,
    // use whichever one actually has data.
    function extractLensMatches(results) {
      const candidates = ['organic', 'images', 'visualMatches', 'items', 'results'];
      for (const field of candidates) {
        if (Array.isArray(results[field]) && results[field].length > 0) {
          return results[field];
        }
      }
      return [];
    }

    const matches = extractLensMatches(data);
    const results = matches.slice(0, 5).map(function(item) {
      return {
        title: item.title || 'Untitled',
        link: item.link || '#',
        snippet: item.snippet || item.description || '',
        thumbnail: item.imageUrl || item.thumbnailUrl || null,
        source: item.source || item.siteName || ''
      };
    });

    res.json({ success: true, query: query || 'image search', results });
  } catch (error) {
    console.error('Serper lens search error:', error.message);
    res.status(500).json({ success: false, error: 'lens search failed', details: error.message });
  }
});

// ============================================
// WEBPAGE SEARCH API (Serper webpage endpoint)
// ============================================
// The webpage endpoint returns a SINGLE object (not an array), so we wrap
// it in a one-element array to keep the frontend rendering uniform.
// ============================================
// WEBPAGE SCRAPE API (Serper scrape endpoint)
// ============================================
// Serper's webpage-scraping feature uses a completely separate domain from the
// regular SERP endpoints. It POSTs to https://scrape.serper.dev with body
// { url, includeMarkdown: true } and the same X-API-KEY header.
//
// This is NOT at google.serper.dev/webpage — that endpoint doesn't exist.
// The correct URL is: https://scrape.serper.dev
//
// NOTE: Images and other media embedded in the scraped page may not be included
// in the returned text. This feature is for extracting the textual content of a
// webpage, not for full rendering. See the ethical notice below.
app.post('/api/search-webpage', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string' || !url.trim()) {
      return res.status(400).json({ error: 'A URL is required' });
    }

    let targetUrl = url.trim();

    // Auto-add https:// if the user typed a bare domain like "google.com"
    if (!/^https?:\/\//i.test(targetUrl)) {
      targetUrl = 'https://' + targetUrl;
    }

    const data = await callSerper('https://scrape.serper.dev', { url: targetUrl, includeMarkdown: true });
    res.json({ success: true, data: data });
  } catch (err) {
    console.error('Webpage scrape error:', err.message);
    res.status(500).json({ error: 'Could not fetch that webpage. Please check the URL and try again.' });
  }
});

// ============================================
// AUTOCOMPLETE SEARCH API (Serper autocomplete endpoint)
// ============================================
// The autocomplete endpoint returns { suggestions: ["...", "..."] } — a flat
// list of strings. We map each suggestion to a result object so the frontend
// can render them uniformly.
app.post('/api/search-autocomplete', createSerperSearchRoute('autocomplete', function(data) {
  return (data.suggestions || []).slice(0, 10).map(function(suggestion) {
    return {
      title: suggestion,
      link: null,
      snippet: ''
    };
  });
}));

// ============================================
// PATENTS SEARCH API (Serper patents endpoint)
// ============================================
app.post('/api/search-patents', createSerperSearchRoute('patents', function(data) {
  return (data.patents || []).slice(0, 5).map(function(item) {
    return {
      title: item.title || 'Untitled',
      link: item.link || '#',
      inventor: item.inventor || '',
      filingDate: item.filingDate || '',
      publicationDate: item.publicationDate || '',
      assignee: item.assignee || '',
      status: item.status || '',
      snippet: item.snippet || ''
    };
  });
}));

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
  openrouter: 'openai/gpt-oss-20b:free',  // NEW
};

const FALLBACK_ORDER = ['gemini', 'groq', 'bigmodel', 'openrouter'];

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
  let justSavedFact = null;

  // ---- Explicit save-to-memory requests: detect & save IMMEDIATELY (guaranteed) ----
  // This bypasses the probabilistic Groq classifier used for automatic/implicit
  // extraction, which can sometimes decide not to save something even when it should.
  const lastUserMsg = [...messages].reverse().find(m => m.role === 'user');
  if (lastUserMsg && typeof lastUserMsg.content === 'string') {
    if (detectExplicitMemoryRequest(lastUserMsg.content)) {
      // Explicit request — save immediately and guaranteed, awaited (not
      // fire-and-forget) so it's saved before the response streams back.
      try {
        const fact = await extractExplicitMemoryFact(lastUserMsg.content);
        await addMemory(req.username, fact);
        justSavedFact = fact;
        console.log('Explicitly saved to memory for', req.username, ':', fact);
      } catch (err) {
        console.error('Explicit memory save failed:', err.message);
      }
    } else {
      // No explicit request — keep the existing automatic, probabilistic
      // background extraction as before (fire-and-forget).
      extractMemoryFact(lastUserMsg.content).then(fact => {
        if (fact) addMemory(req.username, fact);
      });
    }
  }

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

  // If an explicit save just happened, let the AI acknowledge it in its response
  if (justSavedFact) {
    systemParts.push(
      `The user just explicitly asked you to remember something, and it has ` +
      `been saved successfully: "${justSavedFact}". Briefly acknowledge that ` +
      `you'll remember it as part of your response.`
    );
  }

  // Inject this user's saved memory
  const memoryFacts = await getMemory(req.username);
  console.log('Memory fetched for', req.username, ':', memoryFacts.length, 'fact(s)');
  if (memoryFacts.length > 0) {
    // Use stronger, more directive language to ensure the model actually uses the memory
    // IMPORTANT: Warn the model that facts may be about other people/things, not necessarily the user
    systemParts.push(
      `=== IMPORTANT: SAVED USER MEMORY ===\n` +
      `The following are facts the user has explicitly asked you to remember. ` +
      `These facts may be about the user themselves, OR about other people/things ` +
      `they mentioned (e.g. a friend, a favorite player, a family member) — ` +
      `do NOT assume a fact describes the user unless it clearly says so ` +
      `(e.g. "my name is...", "I am...", "I live in..."). ` +
      `In particular, NEVER address the user by a name mentioned in these facts ` +
      `unless the fact explicitly states that is the user\'s own name.\n` +
      `When the user asks a personal question (e.g. about their favorite person, ` +
      `preferences, location, job, etc.), check this list first and answer directly ` +
      `using this information if relevant — do NOT say you don\'t know if the answer is here.\n` +
      memoryFacts.map(function(f) { return '- ' + f; }).join('\n') +
      `\n=== END SAVED MEMORY ===\n\nUse this information naturally when relevant, without explicitly mentioning that it came from "memory".`
    );
  }

  // Web search injection
  // Skip web search for trivial/very short messages — even with the search toggle
  // on, a message this short can't meaningfully benefit from search results, and
  // short casual words (e.g. "okk", "hi", "thanks") can accidentally match unrelated
  // company/product names, pulling in large irrelevant content for no benefit.
  const CASUAL_MESSAGE_PATTERN = /^(okk?|ok|hi|hii+|hey|hello|thanks?|thank you|dhonnobad|thik ?ache?|accha?|hmm+|hm+|k+|yes|no|na|ha+)\.?!?$/i;
  
  function shouldSkipSearch(userMessage) {
    if (!userMessage) return true;
    const trimmed = userMessage.trim();
    if (trimmed.length < 4) return true; // too short to need search
    if (CASUAL_MESSAGE_PATTERN.test(trimmed)) return true; // matches a known casual/filler word
    return false;
  }
  
  // Limit search results to a small, relevant set — prevents huge raw scraped
  // content from bloating the system prompt and wasting tokens.
  const MAX_SEARCH_RESULTS = 3;
  const MAX_SNIPPET_LENGTH = 300; // characters per result
  
  function buildSearchResultsText(results) {
    if (!results || results.length === 0) return '';
    
    const trimmedResults = results.slice(0, MAX_SEARCH_RESULTS).map(function(r, i) {
      const title = (r.title || '').trim();
      let snippet = (r.snippet || r.content || r.description || '').trim();
      if (snippet.length > MAX_SNIPPET_LENGTH) {
        snippet = snippet.slice(0, MAX_SNIPPET_LENGTH) + '...';
      }
      return '[' + (i + 1) + '] ' + title + '\n' + snippet + '\nSource: ' + (r.link || r.url || '');
    });
    
    return trimmedResults.join('\n\n');
  }
  
  if (webSearch && !shouldSkipSearch(lastUserMsg ? lastUserMsg.content : '')) {
    try {
      const lastUserMsg = [...messages].reverse().find(m => m.role === 'user');
      const query = lastUserMsg ? lastUserMsg.content : '';

      const results = await searchWeb(query);
      sources = results.slice(0, MAX_SEARCH_RESULTS).map(r => ({ title: r.title, link: r.url }));

      const context = buildSearchResultsText(results);

      systemParts.push(`You have access to the following up-to-date web search results. Use them to answer the user's question accurately. Cite sources using [1], [2] etc. where relevant. If not relevant, answer using your own knowledge instead.\n\nWeb Search Results:\n${context}`);
    } catch (err) {
      console.error('Web search failed, proceeding without it:', err.message);
    }
  }

  // Always create finalMessages with system message, even if systemParts is empty
  // This ensures consistent structure and prevents missing system messages
  const systemMessageContent = systemParts.length > 0 
    ? systemParts.join('\n\n---\n\n') 
    : 'You are a helpful assistant.';
  
  // Filter out any system messages from the incoming messages array to avoid duplicates
  // (the frontend may send its own system message, but we want exactly one)
  const nonSystemMessages = messages.filter(function(m) { return m.role !== 'system'; });
  finalMessages = [{ role: 'system', content: systemMessageContent }, ...nonSystemMessages];

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

// ============================================
// AI IMAGE GENERATION via Pollinations.ai (free, no API key)
// ============================================
app.post('/api/generate-image', async (req, res) => {
    const { prompt } = req.body;

    // Validate prompt
    if (!prompt || !prompt.trim()) {
        return res.status(400).json({
            success: false,
            error: 'Prompt is required'
        });
    }

    try {
        console.log(`🎨 Generating image for prompt: ${prompt}`);

        // Enhance the prompt for better results (same approach as /imagine)
        const enhancedPrompt = await enhanceImagePrompt(prompt.trim());
        console.log('Image prompt — original:', prompt.trim(), '| enhanced:', enhancedPrompt);

        // Generate via Pollinations.ai — free, no API key required
        const image = await generateImageWithPollinations(enhancedPrompt);

        console.log('✅ Image generated successfully');

        return res.json({
            success: true,
            prompt: prompt.trim(),
            image: `data:${image.mimeType};base64,${image.base64}`
        });

    } catch (error) {
        console.error('❌ Image generation error:', error.message);

        return res.status(500).json({
            success: false,
            error: 'Image generation failed',
            details: error.message
        });
    }
});

// ---- Reusable "kontext" image-editing pipeline ----
// Sends an image buffer + prompt through Pollinations' OpenAI-compatible
// /v1/images/edits endpoint (model: kontext) and returns a base64 data URL.
// Handles JSON (url / b64_json) and raw-binary responses, and sniffs the
// actual image format so the data:image/...;base64,... prefix is correct.
async function editImageWithKontext(imageBuffer, mimeType, prompt) {
    // The gen.pollinations.ai/v1/images/edits endpoint requires an API key via
    // the Authorization header. Fail fast with a clear error if it's not
    // configured, so misconfiguration is obvious in the logs rather than a
    // generic 401 from the provider.
    if (!process.env.POLLINATIONS_API_KEY) {
        throw new Error('POLLINATIONS_API_KEY is not configured on the server');
    }

    const detectedMimeType = mimeType || 'image/jpeg';
    const fileExt = detectedMimeType.indexOf('png') !== -1 ? 'png' : 'jpg';

    // Build the multipart form body
    const form = new FormData();
    form.append('image', imageBuffer, {
        filename: 'input.' + fileExt,
        contentType: detectedMimeType
    });
    form.append('prompt', prompt.trim());
    form.append('model', 'kontext');

    // Send to Pollinations' OpenAI-compatible image-edits endpoint.
    // Accepts the uploaded file directly via multipart — no public URL needed.
    let response;
    try {
        response = await axios.post(
            'https://gen.pollinations.ai/v1/images/edits',
            form,
            {
                headers: Object.assign({}, form.getHeaders(), {
                    'Authorization': 'Bearer ' + process.env.POLLINATIONS_API_KEY
                }),
                responseType: 'arraybuffer',
                timeout: 120000
            }
        );
    } catch (err) {
        // Pollinations returns 402 Payment Required when the account's Pollen
        // credits are exhausted. Surface a clear, user-friendly message so the
        // frontend can show it directly instead of a generic failure.
        if (err.response && err.response.status === 402) {
            throw new Error('POLLEN_CREDITS_EXHAUSTED');
        }
        throw err;
    }

    // ---- Determine the response format (JSON vs raw binary) ----
    // The OpenAI-compatible /v1/images/edits endpoint typically returns JSON
    // ({ "data": [ { "url": ... } ] } or { "data": [ { "b64_json": ... } ] }),
    // NOT raw image bytes — so the old buffer-to-base64 logic could produce a
    // corrupted file. Log what we actually got so it's visible in Render logs.
    const contentTypeHeader = String(response.headers['content-type'] || '');
    const rawResponseBuf = Buffer.isBuffer(response.data) ? response.data : Buffer.from(response.data);
    const headSnippet = rawResponseBuf.toString('utf8', 0, 200);
    console.log('Pollinations edit response content-type:', contentTypeHeader);
    console.log('Pollinations edit response first 200 chars:', headSnippet);

    let base64Image;
    let resultMimeType;

    if (contentTypeHeader.indexOf('application/json') !== -1 || headSnippet.trim().startsWith('{')) {
        // ---- OpenAI-style JSON response ----
        let parsed;
        try {
            parsed = JSON.parse(rawResponseBuf.toString('utf8'));
        } catch (err) {
            throw new Error('Failed to parse JSON response from image-edits endpoint: ' + err.message);
        }

        const item = parsed && parsed.data && parsed.data[0];
        if (!item) {
            const errDetail = (parsed && parsed.error && (parsed.error.message || JSON.stringify(parsed.error))) || JSON.stringify(parsed);
            throw new Error('Pollinations image edit returned no data: ' + errDetail);
        }

        if (item.b64_json) {
            // Base64 image directly in the JSON response.
            // OpenAI b64_json payloads are PNGs by default, but Pollinations may
            // return JPEG or WebP — sniff the actual format from the magic bytes
            // so the data:image/...;base64,... prefix matches the real content.
            base64Image = item.b64_json.replace(/^data:image\/[a-zA-Z0-9.+-]+;base64,/, '');
            const header = base64Image.slice(0, 24);
            if (header.indexOf('/9j/') === 0) {
                resultMimeType = 'image/jpeg';
            } else if (header.indexOf('iVBORw0KGgo') === 0) {
                resultMimeType = 'image/png';
            } else if (header.indexOf('UklGR') === 0) {
                resultMimeType = 'image/webp';
            } else if (header.indexOf('R0lGOD') === 0) {
                resultMimeType = 'image/gif';
            } else {
                resultMimeType = 'image/png'; // safe default
            }
        } else if (item.url) {
            // The JSON gives us a URL — fetch it server-side and convert to base64
            const imgResp = await fetchWithTimeout(item.url, {}, 120000);
            if (!imgResp.ok) {
                throw new Error('Failed to fetch edited image from returned URL, status ' + imgResp.status);
            }
            const imgBuffer = await imgResp.buffer();
            base64Image = imgBuffer.toString('base64');
            resultMimeType = (imgResp.headers.get('content-type') || 'image/png').split(';')[0].trim() || 'image/png';
        } else {
            throw new Error('Pollinations image edit response had neither url nor b64_json');
        }
    } else {
        // ---- Raw binary image data ----
        // response.data is already a Buffer (responseType: 'arraybuffer') —
        // do NOT re-encode through latin1, which corrupts binary data.
        base64Image = rawResponseBuf.toString('base64');
        resultMimeType = (contentTypeHeader || 'image/png').split(';')[0].trim() || 'image/png';
    }

    console.log('✅ Image edited successfully (' + resultMimeType + ')');

    return `data:${resultMimeType};base64,${base64Image}`;
}

// ============================================
// AI IMAGE EDITING via Pollinations.ai kontext model (image-to-image)
// ============================================
// Pollinations' "kontext" model supports image-to-image editing. No API key or
// billing is required for basic usage — though free/anonymous requests may include
// a watermark and have lower rate limits than authenticated usage.
//
// We use the OpenAI-compatible endpoint (https://gen.pollinations.ai/v1/images/edits)
// which accepts the image as a multipart file upload directly ("image=@file"),
// rather than the URL-based endpoint that requires a publicly accessible image URL.
app.post('/api/edit-image', async (req, res) => {
    const { image, mimeType, prompt } = req.body;

    // Validate inputs
    if (!prompt || !prompt.trim()) {
        return res.status(400).json({
            success: false,
            error: 'Prompt is required'
        });
    }

    if (!image) {
        return res.status(400).json({
            success: false,
            error: 'Image is required'
        });
    }

    try {
        console.log(`🎨 Editing image with prompt: ${prompt}`);

        // Strip any "data:image/...;base64," prefix if present (defensive)
        const commaIndex = image.indexOf(',');
        const cleanBase64 = image.startsWith('data:') && commaIndex !== -1
            ? image.slice(commaIndex + 1)
            : image;

        // Convert base64 to a Buffer for the multipart upload
        const imageBuffer = Buffer.from(cleanBase64, 'base64');

        const dataUrl = await editImageWithKontext(imageBuffer, mimeType, prompt);

        return res.json({
            success: true,
            prompt: prompt.trim(),
            image: dataUrl
        });

    } catch (error) {
        console.error('❌ Image edit error:', error.message);

        // Pollinations returned 402 (Pollen credits exhausted) — surface a clear,
        // user-friendly message so the frontend can show it directly instead of a
        // generic "Image editing failed". There is no free alternative for this
        // feature (editing a user-uploaded photo requires the kontext model).
        if (error.message === 'POLLEN_CREDITS_EXHAUSTED') {
            return res.status(402).json({
                success: false,
                error: 'Image editing requires Pollinations credits (Pollen), which are currently exhausted. Please top up Pollen at enter.pollinations.ai, or try again later if free quota resets.'
            });
        }

        return res.status(500).json({
            success: false,
            error: 'Image editing failed',
            details: error.message
        });
    }
});

// ============================================
// SEARCH-AND-POLISH IMAGE GENERATION
// ============================================
// Finds a real photo via Serper's image search and returns it directly.
// NOTE: This route intentionally does NOT run the photo through the
// Pollinations "kontext" pipeline — that costs Pollen credits, which we
// avoid for this feature. It only uses Serper (SERPER_API_KEY) to find a
// photo, fetches it, and returns it as a base64 data URL. If no suitable
// photo can be found or fetched, it falls back to the free plain
// text-to-image Pollinations flow (image.pollinations.ai, no key needed).
//
// ⚠️ COPYRIGHT / ETHICAL NOTICE ⚠️
// Images found via web search may be copyrighted and belong to their original
// photographers/sites. This feature should ONLY be used for personal /
// non-commercial purposes. Real people's photos found this way should NOT be
// used without their consent, and especially NOT for any sexual or defamatory
// editing. The frontend should disclose (via sourceNote) that the result is
// based on a real photo, not pure AI generation.
app.post('/api/generate-image-from-search', async (req, res) => {
    const { prompt } = req.body;

    // Validate prompt
    if (!prompt || !prompt.trim()) {
        return res.status(400).json({
            success: false,
            error: 'Prompt is required'
        });
    }

    const userPrompt = prompt.trim();

    // ---- Fallback: plain text-to-image (free, image.pollinations.ai, no key) ----
    // Reused by all failure paths below: search fails, no results, or fetch fails.
    async function fallbackToTextToImage(reasonNote) {
        console.log('🎨 Falling back to pure text-to-image generation for:', userPrompt, '|', reasonNote);
        try {
            const enhancedPrompt = await enhanceImagePrompt(userPrompt);
            const image = await generateImageWithPollinations(enhancedPrompt);
            return res.json({
                success: true,
                prompt: userPrompt,
                image: `data:${image.mimeType};base64,${image.base64}`,
                sourceNote: 'AI-generated (no matching real photo found)'
            });
        } catch (fallbackErr) {
            console.error('❌ Fallback text-to-image failed:', fallbackErr.message);
            return res.status(500).json({
                success: false,
                error: 'Image generation failed',
                details: fallbackErr.message
            });
        }
    }

    // ---- Browser-like headers for fetching images ----
    // Some sites (e.g. Wikipedia) block requests with no User-Agent at all.
    // A realistic browser UA + Referer dramatically improves fetch success rate.
    const BROWSER_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': 'https://www.google.com/',
        'Cache-Control': 'no-cache'
    };

    // ---- Step 1: Search Serper for real photos ----
    // Exclude known-blocking domains from the query so Serper doesn't waste
    // results on sites that will 403/429 our server-side fetch anyway.
    const BLOCKED_SITES = ' -site:instagram.com -site:facebook.com -site:pinterest.com -site:tiktok.com';
    const searchQuery = userPrompt + BLOCKED_SITES;

    let candidateUrls = [];
    try {
        if (!process.env.SERPER_API_KEY) {
            throw new Error('SERPER_API_KEY is not configured');
        }

        const searchData = await callSerper('https://google.serper.dev/images', {
            q: searchQuery,
            num: 10  // request more results so we have candidates to try in order
        });
        const results = searchData.images || [];

        // Collect ALL candidate URLs (prefer larger images first, but keep every
        // result with a URL so we can loop through them until one fetches).
        const largeCandidates = results.filter(function(r) {
            return r.imageUrl && (r.imageWidth || 0) >= 400 && (r.imageHeight || 0) >= 400;
        });
        const anyCandidates = results.filter(function(r) { return r.imageUrl; });

        candidateUrls = (largeCandidates.length > 0 ? largeCandidates : anyCandidates)
            .map(function(r) { return r.imageUrl; })
            .slice(0, 10); // cap at 10 attempts max

        if (candidateUrls.length > 0) {
            console.log('🔍 Found ' + candidateUrls.length + ' candidate photo(s) via Serper for:', userPrompt);
        } else {
            console.log('🔍 Serper returned no usable image results for:', userPrompt);
        }
    } catch (err) {
        console.error('🔍 Serper image search failed:', err.message);
    }

    // ---- Step 2: If no photo found, fall back to plain text-to-image ----
    if (candidateUrls.length === 0) {
        return fallbackToTextToImage('no photo found');
    }

    // ---- Step 3: Try fetching each candidate in order, use the first that succeeds ----
    // Each attempt gets a short 8-second timeout so a slow/blocked source doesn't
    // stall the whole request — we move to the next candidate quickly.
    const MAX_ATTEMPT_TIMEOUT = 8000; // 8 seconds per candidate
    const MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10MB max

    for (let i = 0; i < candidateUrls.length; i++) {
        const imageUrl = candidateUrls[i];
        console.log('📥 Attempt ' + (i + 1) + '/' + candidateUrls.length + ' fetching:', imageUrl);

        try {
            const fetchResponse = await axios.get(imageUrl, {
                responseType: 'arraybuffer',
                timeout: MAX_ATTEMPT_TIMEOUT,
                maxContentLength: MAX_IMAGE_SIZE,
                maxBodyLength: MAX_IMAGE_SIZE,
                headers: BROWSER_HEADERS
            });

            // Validate: status 200 + valid image content-type
            const ct = String(fetchResponse.headers['content-type'] || '').toLowerCase();
            const isValidImageType = ct.indexOf('image/') === 0 ||
                ct.indexOf('jpeg') !== -1 || ct.indexOf('jpg') !== -1 ||
                ct.indexOf('png') !== -1 || ct.indexOf('webp') !== -1 ||
                ct.indexOf('gif') !== -1;

            if (!isValidImageType) {
                console.log('⚠️ Attempt ' + (i + 1) + ' rejected: not an image content-type (' + ct + ')');
                continue; // try next candidate
            }

            const imageBuffer = Buffer.from(fetchResponse.data);
            if (imageBuffer.length === 0) {
                console.log('⚠️ Attempt ' + (i + 1) + ' rejected: empty response body');
                continue; // try next candidate
            }

            let fetchedMimeType = 'image/jpeg';
            if (ct.indexOf('png') !== -1) fetchedMimeType = 'image/png';
            else if (ct.indexOf('webp') !== -1) fetchedMimeType = 'image/webp';
            else if (ct.indexOf('gif') !== -1) fetchedMimeType = 'image/gif';
            else if (ct.indexOf('jpeg') !== -1 || ct.indexOf('jpg') !== -1) fetchedMimeType = 'image/jpeg';

            const base64Image = imageBuffer.toString('base64');
            console.log('✅ Fetched real photo on attempt ' + (i + 1) + ' (' + fetchedMimeType + ', ' + imageBuffer.length + ' bytes) — returning directly');

            return res.json({
                success: true,
                prompt: userPrompt,
                image: `data:${fetchedMimeType};base64,${base64Image}`,
                sourceNote: 'Real photo from web search'
            });
        } catch (err) {
            console.log('⚠️ Attempt ' + (i + 1) + ' failed (' + err.message + ') — trying next candidate');
            // Continue to the next candidate — do NOT fall back yet
        }
    }

    // ---- Step 4: ALL candidates failed — only now fall back to text-to-image ----
    console.error('📥 All ' + candidateUrls.length + ' candidate photo(s) failed to fetch, falling back to text-to-image');
    return fallbackToTextToImage('all ' + candidateUrls.length + ' photo fetch attempts failed');
});

// ============================================
// IMAGE GENERATION (free, via Pollinations.ai — no API key, no limits)
// ============================================

// ---- Quality-boost keywords: appended to enhanced prompts if not already present ----
// These terms noticeably improve the output of Pollinations' diffusion models without
// making prompts overly long or repetitive (we skip them if the prompt already contains
// similar quality language).
const QUALITY_BOOST_KEYWORDS = ', highly detailed, sharp focus, professional photography, 8k, high resolution, perfect anatomy, correct proportions, detailed hands, detailed fingers, subject in sharp focus, crisp facial details, tack sharp, high clarity, in-focus subject';

const QUALITY_TERMS = [
  'highly detailed', 'detailed',
  'sharp focus', 'sharp',
  'professional photography', 'professional',
  '8k', '4k',
  'high resolution', 'hi-res', 'hires',
  'ultra hd', 'uhd',
  'high quality', 'photorealistic', 'hyperrealistic'
];

function appendQualityBoost(prompt) {
  const lowered = String(prompt).toLowerCase();
  const alreadyHasQuality = QUALITY_TERMS.some(function(term) { return lowered.indexOf(term) !== -1; });
  if (alreadyHasQuality) return prompt;
  return prompt + QUALITY_BOOST_KEYWORDS;
}

// ---- Enhance (and translate if needed) prompts before sending to Pollinations ----
// Pollinations.ai's underlying image model produces much better results when given
// a vivid, detailed, well-structured English prompt. This helper uses the existing
// Gemini integration to rewrite ANY prompt (English or non-English) into a more
// descriptive, composition-aware prompt — adding lighting, mood, and style details
// while staying faithful to what the user actually asked for. This significantly
// improves output quality for any diffusion-based image model.
async function enhanceImagePrompt(userPrompt) {
    try {
        const url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=' + process.env.GEMINI_API_KEY;
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{
                    role: 'user',
                    parts: [{
                        text: 'You are an expert AI image generation prompt writer. Take the user\'s request below ' +
                              '(it may be in any language) and rewrite it as a single, vivid, highly descriptive ' +
                              'English prompt suitable for an AI image generator. Include relevant details like ' +
                              'composition, lighting, mood, and art style/photography style if not already specified, ' +
                              'while staying faithful to what the user actually asked for — do not change the subject ' +
                              'or add unrelated elements. IMPORTANT RULES: ' +
                              'The SUBJECT must always be in sharp focus with crisp, detailed features — never soft, dreamy, or hazy. ' +
                              'Any bokeh, dreamy, soft-focus, or soft-light effects MUST be explicitly scoped to the BACKGROUND ONLY ' +
                              '(e.g. "background softly blurred with bokeh", "golden hour lighting on the background") ' +
                              'so they do not soften the subject itself. ' +
                              'Do not use vague unscoped words like "soft" or "dreamy" to describe the whole image. ' +
                              'Output ONLY the final prompt text, nothing else — ' +
                              'no quotes, no explanation, no labels.\n\n' +
                              'User request: ' + userPrompt
                    }]
                }]
            })
        });

        if (!response.ok) {
            console.warn('Prompt enhancement failed with status ' + response.status + ', using original prompt');
            return appendQualityBoost(userPrompt);
        }

        const data = await response.json();
        const enhanced = data.candidates &&
            data.candidates[0] &&
            data.candidates[0].content &&
            data.candidates[0].content.parts &&
            data.candidates[0].content.parts[0] &&
            data.candidates[0].content.parts[0].text;

        return enhanced ? appendQualityBoost(enhanced.trim()) : appendQualityBoost(userPrompt);
    } catch (err) {
        console.warn('Prompt enhancement error, using original prompt:', err.message);
        return appendQualityBoost(userPrompt); // never let enhancement failure block image generation
    }
}

async function generateImageWithPollinations(prompt) {
  const encodedPrompt = encodeURIComponent(prompt);
  const seed = Math.floor(Math.random() * 1000000); // random seed so the same prompt doesn't return an identical cached image every time
  const imageUrl = 'https://image.pollinations.ai/prompt/' + encodedPrompt +
    '?seed=' + seed +
    '&model=flux' +             // much higher quality than the default model
    '&width=1536&height=1536' + // high resolution output
    '&enhance=true' +           // enable Pollinations built-in image enhancement
    '&negative=' + encodeURIComponent('deformed hands, extra fingers, missing fingers, fused fingers, malformed limbs, bad anatomy, blurry, disfigured, mutated, extra limbs') +
    '&nologo=true';

  const response = await fetch(imageUrl);
  if (!response.ok) {
    throw new Error('Pollinations image generation failed with status ' + response.status);
  }

  const buffer = await response.buffer(); // node-fetch v2 style
  const base64Image = buffer.toString('base64');
  return {
    base64: base64Image,
    mimeType: 'image/jpeg'
  };
}

// ---- POST /imagine — generate an image from a text prompt (auth required) ----
app.post('/imagine', requireAuth, async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
      return res.status(400).json({ error: 'A prompt is required' });
    }

    const enhancedPrompt = await enhanceImagePrompt(prompt.trim());
    console.log('Image prompt — original:', prompt.trim(), '| enhanced:', enhancedPrompt);

    const image = await generateImageWithPollinations(enhancedPrompt);
    res.json({
      imageBase64: image.base64,
      mimeType: image.mimeType,
      prompt: prompt.trim() // still show the user's original text in chat, not the enhanced version
    });
  } catch (err) {
    console.error('Image generation failed:', err.message);
    res.status(500).json({ error: 'Sorry, I could not generate the image. Please try again.' });
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

  return fetchWithTimeout(url, {
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
  } else if (provider === 'openrouter') {
    url = 'https://openrouter.ai/api/v1/chat/completions';
  }

  const headers = {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json'
  };
  // OpenRouter requires HTTP-Referer and X-Title on every request, otherwise it
  // may silently reject or hang. Other providers only need the basics.
  if (provider === 'openrouter') {
    headers['HTTP-Referer'] = process.env.APP_URL || 'https://rabbyziljalal.github.io';
    headers['X-Title'] = 'Multi-AI Chatbot';
  }

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

  return fetchWithTimeout(url, {
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
