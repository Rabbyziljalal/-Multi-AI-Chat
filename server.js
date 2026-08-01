const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fetch = require('node-fetch');
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

// Vision-capable models
const VISION_MODELS = {
  openai: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo'],
  gemini: ['gemini-2.5-flash-lite', 'gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-2.0-flash'],
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
// AI CHAT ROUTE (updated with webSearch support)
// ============================================
app.post('/chat', async (req, res) => {
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

  // If webSearch is requested, search first and inject context
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
        content: `You have access to the following up-to-date web search results. Use them to answer the user's question accurately. Cite sources using [1], [2] etc. where relevant. If the search results are not relevant to the question, answer using your own knowledge instead.\n\nWeb Search Results:\n${context}`
      };

      // Put the search context right before the last user message
      finalMessages = [...messages];
      finalMessages.splice(finalMessages.length - 1, 0, searchSystemMsg);

    } catch (err) {
      console.error('Web search failed, proceeding without it:', err.message);
      // Fall back to normal chat without search context
    }
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