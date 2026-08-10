const fetch = require('node-fetch');
const { PassThrough } = require('stream');

// Persists across requests for the lifetime of this server process (in-memory).
// Used to alternate which Gemini key is tried first on each request.
let geminiKeyToggleCounter = 0;

// ---- Fetch wrapper with a timeout ----
// If a provider doesn't respond within the window (default 20s), the request is
// aborted and throws — the existing try/catch in getStreamingResponse treats that
// as a failure and moves to the next attempt, instead of hanging forever.
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(function() { controller.abort(); }, timeoutMs || 8000);
  try {
    const response = await fetch(url, Object.assign({}, options, { signal: controller.signal }));
    clearTimeout(timeout);
    return response;
  } catch (err) {
    clearTimeout(timeout);
    throw err; // aborted/timed-out request throws here — handled as a failure by the caller
  }
}

// ---- Verify the response BODY actually starts flowing before committing to it ----
// The earlier timeout only covered the connection/headers phase. After response.ok
// is confirmed, the body can still stall indefinitely with zero data. This helper
// waits up to `timeoutMs` (default 10s) for the FIRST real chunk to arrive. If it
// arrives, we return a PassThrough stream that replays that first chunk followed
// by the rest — so nothing is lost. If it times out, we throw — the caller treats
// it as a failed attempt and moves to the next fallback BEFORE any headers have
// been sent to the actual frontend client.
async function waitForFirstChunk(response, timeoutMs) {
  return new Promise(function(resolve, reject) {
    const source = response.body; // node-fetch v2: a Node.js Readable stream
    const pass = new PassThrough();

    let settled = false;
    const timeout = setTimeout(function() {
      if (settled) return;
      settled = true;
      reject(new Error('No response data received within ' + timeoutMs + 'ms'));
    }, timeoutMs || 6000);

    // Pause the source so we can safely read the first chunk without losing data
    source.pause();

    function onError(err) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(err);
    }

    function onEnd() {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      pass.end();
      resolve(pass);
    }

    function onReadable() {
      if (settled) return;
      // Read the first chunk (returns null if not ready yet)
      const firstChunk = source.read();
      if (firstChunk === null) return;

      settled = true;
      clearTimeout(timeout);
      source.removeListener('readable', onReadable);
      source.removeListener('end', onEnd);
      source.removeListener('error', onError);

      // Replay the consumed first chunk, then pipe the rest of the original stream
      pass.write(firstChunk);
      source.pipe(pass);
      resolve(pass);
    }

    source.once('readable', onReadable);
    source.once('end', onEnd);
    source.once('error', onError);
  });
}

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

  const response = await fetchWithTimeout(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return { response: response, isGemini: true };
}

async function callOpenAICompatRaw(baseUrl, apiKey, model, messages, imageBase64, imageMimeType, pdfText, provider) {
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

  // Build headers — OpenRouter requires HTTP-Referer and X-Title on every request,
  // otherwise it may silently reject or hang. Other providers only need the basics.
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + apiKey
  };
  if (provider === 'openrouter') {
    headers['HTTP-Referer'] = process.env.APP_URL || 'https://rabbyziljalal.github.io';
    headers['X-Title'] = 'Multi-AI Chatbot';
  }

  const response = await fetchWithTimeout(baseUrl, {
    method: 'POST',
    headers: headers,
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
  function pushOpenAICompat(baseUrl, apiKey, model, label, provider) {
    if (!apiKey) return;
    attempts.push({
      label: label,
      run: function() { return callOpenAICompatRaw(baseUrl, apiKey, model, messages, imageBase64, imageMimeType, pdfText, provider); }
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
    pushOpenAICompat('https://open.bigmodel.cn/api/paas/v4/chat/completions', process.env.BIGMODEL_API_KEY, userModel, 'User selection: BigModel (' + userModel + ')', 'bigmodel');
  } else if (userProvider === 'groq') {
    pushOpenAICompat('https://api.groq.com/openai/v1/chat/completions', process.env.GROQ_API_KEY, userModel, 'User selection: Groq (' + userModel + ')', 'groq');
  } else if (userProvider === 'openrouter') {
    pushOpenAICompat('https://openrouter.ai/api/v1/chat/completions', process.env.OPENROUTER_API_KEY, userModel, 'User selection: OpenRouter (' + userModel + ')', 'openrouter');
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

  // 3. BigModel / Groq / OpenRouter — always the final fallback for everyone.
  if (!(userProvider === 'bigmodel')) {
    pushOpenAICompat('https://open.bigmodel.cn/api/paas/v4/chat/completions', process.env.BIGMODEL_API_KEY, 'glm-4-flash', 'Fallback: BigModel', 'bigmodel');
  }
  if (!(userProvider === 'groq')) {
    pushOpenAICompat('https://api.groq.com/openai/v1/chat/completions', process.env.GROQ_API_KEY, 'llama-3.3-70b-versatile', 'Fallback: Groq', 'groq');
  }
  if (!(userProvider === 'openrouter')) {
    pushOpenAICompat('https://openrouter.ai/api/v1/chat/completions', process.env.OPENROUTER_API_KEY, 'openai/gpt-oss-20b:free', 'Fallback: OpenRouter', 'openrouter');
  }

  return attempts;
}

// ---- Try each attempt in order until one returns a healthy (ok) response ----
async function getStreamingResponse(userProvider, userModel, messages, imageBase64, imageMimeType, pdfText) {
  const attempts = buildAttempts(userProvider, userModel, messages, imageBase64, imageMimeType, pdfText);
  let lastError = null;

  for (const attempt of attempts) {
    const attemptStart = Date.now();
    try {
      const result = await attempt.run();
      if (result.response.ok) {
        // Confirm real data actually starts flowing before committing to this attempt.
        // The connection/headers phase succeeding (response.ok) doesn't guarantee the body
        // will stream — it can stall indefinitely with zero data. waitForFirstChunk waits
        // up to 6s for the first real chunk; if it arrives, we return a verified stream.
        // If it times out, it throws — treated as a failure, so the fallback chain moves
        // to the next provider BEFORE any headers are sent to the actual frontend client.
        const verifiedStream = await waitForFirstChunk(result.response, 6000);
        const elapsed = Date.now() - attemptStart;
        console.log('Serving response via: ' + attempt.label + ' (took ' + elapsed + 'ms)');
        return {
          response: { body: verifiedStream, headers: result.response.headers },
          isGemini: result.isGemini,
          servedBy: attempt.label
        };
      }
      const elapsed = Date.now() - attemptStart;
      console.warn(attempt.label + ' failed with status ' + result.response.status + ' (took ' + elapsed + 'ms)');
      lastError = new Error(attempt.label + ' returned ' + result.response.status);
    } catch (err) {
      const elapsed = Date.now() - attemptStart;
      console.warn(attempt.label + ' threw/timed out: ' + err.message + ' (took ' + elapsed + 'ms)');
      lastError = err;
    }
  }

  throw lastError || new Error('All providers failed');
}

module.exports = { getStreamingResponse };