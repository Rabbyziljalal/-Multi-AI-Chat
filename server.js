const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ============================================
// IN-MEMORY AUTH STORE (Render-এ restart হলে reset হবে)
// ============================================
const users = new Map(); // username -> {passwordHash, token}

function hash(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ============================================
// TAVILY WEB SEARCH (Primary)
// ============================================
async function tavilySearch(query) {
  if (!process.env.TAVILY_API_KEY) {
    throw new Error('TAVILY_API_KEY not configured');
  }
  
  const response = await axios.post('https://api.tavily.com/search', {
    api_key: process.env.TAVILY_API_KEY,
    query: query,
    search_depth: 'basic',
    max_results: 5,
    include_answer: true,
    include_images: false
  }, { timeout: 15000 });
  
  return response.data;
}

// ============================================
// SERPER SEARCH (Alternative - যদি Tavily না চলে)
// ============================================
async function serperSearch(query) {
  if (!process.env.SERPER_API_KEY) {
    throw new Error('SERPER_API_KEY not configured');
  }
  
  const response = await axios.post('https://google.serper.dev/search', {
    q: query,
    num: 5
  }, {
    headers: { 'X-API-KEY': process.env.SERPER_API_KEY, 'Content-Type': 'application/json' },
    timeout: 15000
  });
  
  // Convert Serper format to Tavily-like format
  const results = (response.data.organic || []).map(r => ({
    title: r.title,
    url: r.link,
    content: r.snippet || ''
  }));
  
  return { results, answer: null };
}

// ============================================
// SEARCH WRAPPER (Tavily first, fallback Serper)
// ============================================
async function performSearch(query) {
  try {
    return await tavilySearch(query);
  } catch (err) {
    console.log('Tavily failed, trying Serper:', err.message);
    try {
      return await serperSearch(query);
    } catch (err2) {
      throw new Error('Both search providers failed');
    }
  }
}

// ============================================
// HEALTH CHECK
// ============================================
app.get('/', (req, res) => {
  const providers = [];
  if (process.env.OPENAI_API_KEY) providers.push('openai');
  if (process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY_2) providers.push('gemini');
  if (process.env.BIGMODEL_API_KEY) providers.push('bigmodel');
  if (process.env.DEEPSEEK_API_KEY) providers.push('deepseek');
  if (process.env.GROQ_API_KEY) providers.push('groq');
  
  res.json({
    status: 'ok',
    message: 'Multi-AI Chat Backend is running!',
    providers: providers,
    search: process.env.TAVILY_API_KEY ? 'tavily' : (process.env.SERPER_API_KEY ? 'serper' : 'none')
  });
});

// ============================================
// AUTH ROUTES
// ============================================
app.post('/auth/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  for (const [key, val] of users) {
    if (val.username === username) {
      return res.status(409).json({ error: 'Username already exists' });
    }
  }
  
  const token = generateToken();
  users.set(token, { username, passwordHash: hash(password) });
  
  res.json({ token, username });
});

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  for (const [token, data] of users) {
    if (data.username === username && data.passwordHash === hash(password)) {
      return res.json({ token, username });
    }
  }
  
  res.status(401).json({ error: 'Invalid credentials' });
});

// ============================================
// MAIN CHAT ENDPOINT (Streaming SSE)
// ============================================
app.post('/chat', async (req, res) => {
  const { provider, model, messages, webSearch, imageBase64, imageMimeType, pdfText } = req.body;
  
  if (!provider || !model || !messages) {
    return res.status(400).json({ error: 'Missing provider, model, or messages' });
  }

  // Set SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  
  let searchSources = [];
  
  try {
    // ---- 1. WEB SEARCH ----
    let enhancedMessages = JSON.parse(JSON.stringify(messages)); // Deep copy
    
    if (webSearch) {
      const userMsg = messages.find(m => m.role === 'user')?.content || '';
      const searchQuery = userMsg.slice(0, 300);
      
      try {
        const searchData = await performSearch(searchQuery);
        
        if (searchData.results?.length > 0) {
          searchSources = searchData.results.map(r => ({ 
            title: r.title, 
            link: r.url || r.link 
          }));
          
          const context = searchData.results
            .map((r, i) => `[${i + 1}] ${r.title}: ${r.content || r.snippet || ''}`)
            .join('\n\n');
          
          const searchPrompt = `Use the following web search results to help answer the user's question. Cite sources when possible.\n\n${context}\n\n`;
          
          // Inject into system message
          const sysIndex = enhancedMessages.findIndex(m => m.role === 'system');
          if (sysIndex >= 0) {
            enhancedMessages[sysIndex].content = searchPrompt + enhancedMessages[sysIndex].content;
          } else {
            enhancedMessages.unshift({ role: 'system', content: searchPrompt });
          }
        }
      } catch (err) {
        console.error('Search error:', err.message);
      }
    }
    
    // Set search sources header BEFORE writing body
    if (searchSources.length > 0) {
      res.setHeader('X-Search-Sources', encodeURIComponent(JSON.stringify(searchSources)));
    }
    
    // ---- 2. STREAM FROM AI PROVIDER ----
    if (provider === 'gemini') {
      await streamGemini(res, model, enhancedMessages, imageBase64, imageMimeType, pdfText);
    } else {
      await streamOpenAICompatible(res, provider, model, enhancedMessages, imageBase64, imageMimeType, pdfText);
    }
    
  } catch (err) {
    console.error('Chat endpoint error:', err.message);
    res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
    res.write('data: [DONE]\n\n');
    res.end();
  }
});

// ============================================
// GEMINI MODEL MAPPER (Frontend name → Google API name)
// ============================================
const GEMINI_MODEL_MAP = {
  'gemini-flash-latest': 'gemini-1.5-flash-latest',
  'gemini-2.5-pro': 'gemini-2.5-pro-preview-05-06',
  'gemini-1.5-flash': 'gemini-1.5-flash',
  'gemini-1.5-pro': 'gemini-1.5-pro-latest'
};

// ============================================
// GEMINI STREAMING WITH SMART KEY FALLBACK
// ============================================
async function streamGemini(res, model, messages, imageBase64, imageMimeType, pdfText) {
  // Map frontend model name to correct Google API name
  const apiModel = GEMINI_MODEL_MAP[model] || model;
  console.log(`[Gemini] Requested: ${model} → Using API model: ${apiModel}`);
  
  const keys = [
    { key: process.env.GEMINI_API_KEY, name: 'GEMINI_API_KEY' },
    { key: process.env.GEMINI_API_KEY_2, name: 'GEMINI_API_KEY_2' }
  ].filter(k => k.key);
  
  if (keys.length === 0) {
    throw new Error('No Gemini API key configured. Add GEMINI_API_KEY or GEMINI_API_KEY_2 in Render Environment.');
  }

  // Convert OpenAI-style messages to Gemini contents
  const contents = [];
  for (const msg of messages) {
    if (msg.role === 'system') {
      contents.push({ 
        role: 'user', 
        parts: [{ text: `[System Instruction]: ${msg.content}` }] 
      });
      contents.push({ 
        role: 'model', 
        parts: [{ text: 'Understood. I will follow these instructions.' }] 
      });
    } else {
      const parts = [];
      if (msg.content) parts.push({ text: msg.content });
      contents.push({ 
        role: msg.role === 'assistant' ? 'model' : 'user', 
        parts 
      });
    }
  }

  // Attach image to last user message
  if (imageBase64) {
    const lastUserIdx = contents.map((c, i) => c.role === 'user' ? i : -1).filter(i => i >= 0).pop();
    if (lastUserIdx !== undefined) {
      contents[lastUserIdx].parts.push({
        inlineData: {
          mimeType: imageMimeType || 'image/jpeg',
          data: imageBase64
        }
      });
    }
  }

  // Attach PDF text to last user message
  if (pdfText) {
    const lastUserIdx = contents.map((c, i) => c.role === 'user' ? i : -1).filter(i => i >= 0).pop();
    if (lastUserIdx !== undefined) {
      const truncatedPdf = pdfText.slice(0, 15000);
      contents[lastUserIdx].parts.push({ 
        text: `\n\n[PDF Content]:\n${truncatedPdf}` 
      });
    }
  }

  // Try each key until one works
  let lastError = null;
  
  for (const { key, name } of keys) {
    try {
      console.log(`[Gemini] Trying ${name} for model ${apiModel}...`);
      
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${apiModel}:streamGenerateContent?key=${key}`;
      
      const response = await axios.post(url, {
        contents,
        generationConfig: {
          temperature: 0.7,
          maxOutputTokens: 4096
        },
        safetySettings: [
          { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' },
          { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE' },
          { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE' },
          { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' }
        ]
      }, {
        responseType: 'stream',
        timeout: 60000
      });

      console.log(`[Gemini] ✅ ${name} succeeded for ${apiModel}`);
      
      // Pipe NDJSON stream to SSE
      response.data.on('data', (chunk) => {
        const lines = chunk.toString().split('\n');
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const json = JSON.parse(line);
            res.write(`data: ${JSON.stringify(json)}\n\n`);
          } catch (e) {
            // Ignore parse errors for incomplete chunks
          }
        }
      });

      response.data.on('end', () => {
        res.write('data: [DONE]\n\n');
        res.end();
      });

      response.data.on('error', (err) => {
        console.error('[Gemini] Stream error:', err.message);
        res.end();
      });

      return; // SUCCESS! Stop trying other keys.

    } catch (err) {
      const errorMsg = err.response?.data?.error?.message || err.message;
      console.error(`[Gemini] ❌ ${name} failed: ${errorMsg}`);
      lastError = err;
      // Continue to next key
    }
  }

  // All keys failed
  const finalError = lastError?.response?.data?.error?.message || lastError?.message || 'All Gemini API keys failed';
  throw new Error(finalError);
}

// ============================================
// OPENAI-COMPATIBLE STREAMING (OpenAI, BigModel, DeepSeek, Groq)
// ============================================
async function streamOpenAICompatible(res, provider, model, messages, imageBase64, imageMimeType, pdfText) {
  let apiKey, apiUrl;
  
  switch (provider) {
    case 'openai':
      apiKey = process.env.OPENAI_API_KEY;
      apiUrl = 'https://api.openai.com/v1/chat/completions';
      break;
    case 'bigmodel':
      apiKey = process.env.BIGMODEL_API_KEY;
      apiUrl = 'https://open.bigmodel.cn/api/paas/v4/chat/completions';
      break;
    case 'deepseek':
      apiKey = process.env.DEEPSEEK_API_KEY;
      apiUrl = 'https://api.deepseek.com/chat/completions';
      break;
    case 'groq':
      apiKey = process.env.GROQ_API_KEY;
      apiUrl = 'https://api.groq.com/openai/v1/chat/completions';
      break;
    default:
      throw new Error(`Unknown provider: ${provider}`);
  }
  
  if (!apiKey) {
    throw new Error(`No API key configured for ${provider}. Please add ${provider.toUpperCase()}_API_KEY in Render Environment.`);
  }
  
  // Build messages array
  const finalMessages = messages.map(m => ({
    role: m.role,
    content: m.content
  }));
  
  // Handle image (vision)
  if (imageBase64) {
    const lastUserIdx = finalMessages.map((m, i) => m.role === 'user' ? i : -1).filter(i => i >= 0).pop();
    if (lastUserIdx !== undefined) {
      const text = finalMessages[lastUserIdx].content;
      finalMessages[lastUserIdx].content = [
        { type: 'text', text: text || 'What is in this image?' },
        { type: 'image_url', image_url: { url: `data:${imageMimeType || 'image/jpeg'};base64,${imageBase64}` } }
      ];
    }
  }
  
  // Handle PDF text
  if (pdfText) {
    const lastUserIdx = finalMessages.map((m, i) => m.role === 'user' ? i : -1).filter(i => i >= 0).pop();
    if (lastUserIdx !== undefined) {
      const truncated = pdfText.slice(0, 15000);
      const original = finalMessages[lastUserIdx].content;
      
      if (typeof original === 'string') {
        finalMessages[lastUserIdx].content = original + `\n\n[PDF Content]:\n${truncated}`;
      } else if (Array.isArray(original)) {
        const textPart = original.find(p => p.type === 'text');
        if (textPart) textPart.text += `\n\n[PDF Content]:\n${truncated}`;
      }
    }
  }
  
  const response = await axios.post(apiUrl, {
    model,
    messages: finalMessages,
    stream: true,
    temperature: 0.7,
    max_tokens: 4096
  }, {
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    responseType: 'stream',
    timeout: 60000
  });
  
  // Pipe SSE stream directly
  response.data.pipe(res);
  
  response.data.on('error', (err) => {
    console.error(`${provider} stream error:`, err);
    res.end();
  });
  
  res.on('close', () => {
    response.data.destroy();
  });
}

// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log('Available providers:', [
    process.env.OPENAI_API_KEY && 'openai',
    (process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY_2) && 'gemini',
    process.env.BIGMODEL_API_KEY && 'bigmodel',
    process.env.DEEPSEEK_API_KEY && 'deepseek',
    process.env.GROQ_API_KEY && 'groq'
  ].filter(Boolean));
});