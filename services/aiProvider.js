const fetch = require('node-fetch');

// Persists across requests for the lifetime of this server process (in-memory).
// Used to alternate which Gemini key is tried first on each request.
let geminiKeyToggleCounter = 0;

// ---- Defensive helper: strip any "data:image/...;base64," prefix from a base64 string ----
function stripDataUrlPrefix(base64) {
  if (typeof base64 !== 'string') return base64;
  const commaIndex = base64.indexOf(',');
  return base64.startsWith('data:') && commaIndex !== -1
    ? base64.slice(commaIndex + 1)
    : base64;
}

// ---- Individual provider callers ----
// Each one makes the actual HTTP call and returns { response, isGemini } WITHOUT
// reading the streaming body yet — we only check response.ok here, so we can
// fall back to the next provider before committing to streaming anything to the client.

async function callGeminiRaw(apiKey, model, messages, imageBase64, imageMimeType, pdfText) {
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

  const url = 'https://generativelanguage.googleapis.com/v1beta/models/' + model +
    ':streamGenerateContent?alt=sse&key=' + apiKey;

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return { response: response, isGemini: true };
}

async function callOpenAICompatRaw(baseUrl, apiKey, model, messages, imageBase64, imageMimeType, pdfText) {
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
        // Use vision format for all OpenAI-compatible providers
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
      }

      processedMessages.push({ role: 'user', content });
    } else {
      processedMessages.push(msg);
    }
  }

  const response = await fetch(baseUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + apiKey
    },
    body: JSON.stringify({ model: model, messages: processedMessages, stream: true, max_tokens: 4096 })
  });
  return { response: response, isGemini: false };
}

// ---- Build the ordered list of attempts for a given request ----
// userProvider/userModel = whatever the frontend sent (the dropdown selection)
function buildAttempts(userProvider, userModel, messages, imageBase64, imageMimeType, pdfText) {
  const attempts = [];

  function pushGemini(apiKey, model, label) {
    if (!apiKey) return; // skip if that key isn't configured
    attempts.push({
      label: label,
      run: function() { return callGeminiRaw(apiKey, model, messages, imageBase64, imageMimeType, pdfText); }
    });
  }
  function pushOpenAICompat(baseUrl, apiKey, model, label) {
    if (!apiKey) return;
    attempts.push({
      label: label,
      run: function() { return callOpenAICompatRaw(baseUrl, apiKey, model, messages, imageBase64, imageMimeType, pdfText); }
    });
  }

  // Decide this request's key order ONCE, then use it consistently for every
  // Gemini model in the chain below. Flips every request: 1st request tries
  // Key1->Key2, 2nd request tries Key2->Key1, 3rd back to Key1->Key2, etc.
  const useKey1First = (geminiKeyToggleCounter % 2 === 0);
  geminiKeyToggleCounter++;

  const KEY_A = useKey1First ? process.env.GEMINI_API_KEY : process.env.GEMINI_API_KEY_2;
  const KEY_A_LABEL = useKey1First ? 'Key 1' : 'Key 2';
  const KEY_B = useKey1First ? process.env.GEMINI_API_KEY_2 : process.env.GEMINI_API_KEY;
  const KEY_B_LABEL = useKey1First ? 'Key 2' : 'Key 1';

  // Helper: push both keys (in this request's decided order) for a given Gemini model.
  function pushGeminiBothKeys(model, labelPrefix) {
    pushGemini(KEY_A, model, labelPrefix + ' Gemini (' + model + ') ' + KEY_A_LABEL);
    if (KEY_B) {
      pushGemini(KEY_B, model, labelPrefix + ' Gemini (' + model + ') ' + KEY_B_LABEL);
    }
  }

  // 1. Always try the user's actual dropdown selection FIRST — both keys, in
  //    this request's alternating order — before considering any fallback.
  if (userProvider === 'gemini') {
    pushGeminiBothKeys(userModel, 'User selection:');
  } else if (userProvider === 'bigmodel') {
    pushOpenAICompat('https://open.bigmodel.cn/api/paas/v4/chat/completions', process.env.BIGMODEL_API_KEY, userModel, 'User selection: BigModel (' + userModel + ')');
  } else if (userProvider === 'groq') {
    pushOpenAICompat('https://api.groq.com/openai/v1/chat/completions', process.env.GROQ_API_KEY, userModel, 'User selection: Groq (' + userModel + ')');
  }

  // 2. Flash Lite fallback ladder — SKIPPED ENTIRELY if the user specifically
  //    chose gemini-flash-latest (falls straight to BigModel/Groq instead).
  const userChoseFlashLatest = (userProvider === 'gemini' && userModel === 'gemini-flash-latest');

  if (!userChoseFlashLatest) {
    const fallbackModels = ['gemini-3.5-flash-lite', 'gemini-3.1-flash-lite'];
    fallbackModels.forEach(function(m) {
      if (!(userProvider === 'gemini' && userModel === m)) {
        pushGeminiBothKeys(m, 'Fallback:');
      }
    });
  }

  // 3. BigModel / Groq — always the final fallback for everyone.
  if (!(userProvider === 'bigmodel')) {
    pushOpenAICompat('https://open.bigmodel.cn/api/paas/v4/chat/completions', process.env.BIGMODEL_API_KEY, 'glm-4-flash', 'Fallback: BigModel');
  }
  if (!(userProvider === 'groq')) {
    pushOpenAICompat('https://api.groq.com/openai/v1/chat/completions', process.env.GROQ_API_KEY, 'llama-3.3-70b-versatile', 'Fallback: Groq');
  }

  return attempts;
}

// ---- Try each attempt in order until one returns a healthy (ok) response ----
async function getStreamingResponse(userProvider, userModel, messages, imageBase64, imageMimeType, pdfText) {
  const attempts = buildAttempts(userProvider, userModel, messages, imageBase64, imageMimeType, pdfText);
  let lastError = null;

  for (const attempt of attempts) {
    try {
      const result = await attempt.run();
      if (result.response.ok) {
        console.log('Serving response via: ' + attempt.label);
        return result; // { response, isGemini } — caller pipes result.response.body to the client
      }
      console.warn(attempt.label + ' failed with status ' + result.response.status);
      lastError = new Error(attempt.label + ' returned ' + result.response.status);
    } catch (err) {
      console.warn(attempt.label + ' threw: ' + err.message);
      lastError = err;
    }
  }

  throw lastError || new Error('All providers failed');
}

module.exports = { getStreamingResponse };