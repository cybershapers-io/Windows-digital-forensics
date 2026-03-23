/**
 * routes/aiClient.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Unified AI client — supports three backends:
 *
 *   1. LM Studio  — local, air-gapped, OpenAI-compatible
 *                   Set: LM_STUDIO_BASE_URL + LM_STUDIO_MODEL
 *
 *   2. OpenAI     — cloud, GPT-4o / GPT-4 / GPT-3.5 etc.
 *                   Set: OPENAI_API_KEY  (optionally OPENAI_MODEL)
 *
 *   3. Anthropic  — cloud, Claude Sonnet / Haiku / Opus
 *                   Set: ANTHROPIC_API_KEY  (optionally ANTHROPIC_MODEL)
 *
 * Priority (first match wins):  LM Studio  >  OpenAI  >  Anthropic
 *
 * No extra npm packages needed for LM Studio or OpenAI — both use the
 * OpenAI-compatible REST API called via Node's built-in fetch (Node ≥ 18).
 * The Anthropic SDK is only loaded when the Anthropic backend is active.
 * ─────────────────────────────────────────────────────────────────────────────
 */

// ── Backend detection ────────────────────────────────────────────────────────

function getBackend() {
  // ── LM Studio (local) ──────────────────────────────────────────────────────
  const lmBase = (process.env.LM_STUDIO_BASE_URL || '').trim();
  if (lmBase) {
    return {
      type:    'lmstudio',
      label:   'LM Studio',
      base:    lmBase.replace(/\/$/, ''),
      model:   (process.env.LM_STUDIO_MODEL || 'local-model').trim(),
      apiKey:  'lm-studio'   // LM Studio ignores the key value; any string works
    };
  }

  // ── OpenAI (cloud) ─────────────────────────────────────────────────────────
  const openaiKey = (process.env.OPENAI_API_KEY || '').trim();
  if (openaiKey && openaiKey !== 'your_openai_api_key_here') {
    return {
      type:    'openai',
      label:   'OpenAI',
      base:    'https://api.openai.com/v1',
      model:   (process.env.OPENAI_MODEL || 'gpt-4o').trim(),
      apiKey:  openaiKey
    };
  }

  // ── Anthropic (cloud) ──────────────────────────────────────────────────────
  const anthropicKey = (process.env.ANTHROPIC_API_KEY || '').trim();
  if (anthropicKey && anthropicKey !== 'your_anthropic_api_key_here') {
    return {
      type:    'anthropic',
      label:   'Anthropic',
      base:    null,
      model:   (process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514').trim(),
      apiKey:  anthropicKey
    };
  }

  return null;
}

// ── Public API ───────────────────────────────────────────────────────────────

/** Returns true if any AI backend is configured. */
function isConfigured() {
  return getBackend() !== null;
}

/**
 * complete(prompt, maxTokens)
 * Sends a prompt and returns the full response as a plain string.
 */
async function complete(prompt, maxTokens = 3500) {
  const backend = getBackend();
  if (!backend) throw new Error('No AI backend configured. Set LM_STUDIO_BASE_URL, OPENAI_API_KEY, or ANTHROPIC_API_KEY in .env');

  if (backend.type === 'anthropic') {
    return _anthropicComplete(backend, prompt, maxTokens);
  }
  // LM Studio and OpenAI both use OpenAI-compatible /chat/completions
  return _openaiComplete(backend, prompt, maxTokens);
}

/**
 * streamToSSE(prompt, maxTokens, res)
 * Streams the response as Server-Sent Events to the Express response object.
 *   data: {"text":"…"}\n\n  — for each token chunk
 *   data: {"done":true}\n\n  — when finished
 */
async function streamToSSE(prompt, maxTokens = 2000, res) {
  const backend = getBackend();
  if (!backend) throw new Error('No AI backend configured.');

  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');

  if (backend.type === 'anthropic') {
    await _anthropicStream(backend, prompt, maxTokens, res);
  } else {
    await _openaiStream(backend, prompt, maxTokens, res);
  }
}

// ── OpenAI-compatible (LM Studio + OpenAI) ───────────────────────────────────

async function _openaiComplete(backend, prompt, maxTokens) {
  const url  = `${backend.base}/chat/completions`;
  const body = JSON.stringify({
    model:       backend.model,
    max_tokens:  maxTokens,
    temperature: 0.1,
    messages:    [{ role: 'user', content: prompt }]
  });

  let httpRes;
  try {
    httpRes = await fetch(url, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${backend.apiKey}`
      },
      body
    });
  } catch (err) {
    const label = backend.type === 'lmstudio' ? `LM Studio at ${backend.base}` : 'OpenAI';
    throw new Error(`Cannot reach ${label}. Is it running? (${err.message})`);
  }

  if (!httpRes.ok) {
    const errText = await httpRes.text().catch(() => httpRes.statusText);
    throw new Error(`${backend.label} error ${httpRes.status}: ${errText}`);
  }

  const data = await httpRes.json();
  const text = data.choices?.[0]?.message?.content;
  if (!text) throw new Error(`${backend.label} returned an empty response. Is a model loaded?`);
  return text;
}

async function _openaiStream(backend, prompt, maxTokens, res) {
  const url  = `${backend.base}/chat/completions`;
  const body = JSON.stringify({
    model:       backend.model,
    max_tokens:  maxTokens,
    temperature: 0.1,
    stream:      true,
    messages:    [{ role: 'user', content: prompt }]
  });

  let httpRes;
  try {
    httpRes = await fetch(url, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${backend.apiKey}`
      },
      body
    });
  } catch (err) {
    const label = backend.type === 'lmstudio' ? `LM Studio at ${backend.base}` : 'OpenAI';
    throw new Error(`Cannot reach ${label}. Is it running? (${err.message})`);
  }

  if (!httpRes.ok) {
    const errText = await httpRes.text().catch(() => httpRes.statusText);
    throw new Error(`${backend.label} error ${httpRes.status}: ${errText}`);
  }

  const reader  = httpRes.body.getReader();
  const decoder = new TextDecoder();
  let   buf     = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buf += decoder.decode(value, { stream: true });
    const lines = buf.split('\n');
    buf = lines.pop(); // hold incomplete last line

    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const raw = line.slice(6).trim();
      if (raw === '[DONE]') continue;
      try {
        const obj  = JSON.parse(raw);
        const text = obj.choices?.[0]?.delta?.content;
        if (text) res.write(`data: ${JSON.stringify({ text })}\n\n`);
      } catch { /* malformed SSE line — skip */ }
    }
  }

  res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
  res.end();
}

// ── Anthropic ─────────────────────────────────────────────────────────────────

async function _anthropicComplete(backend, prompt, maxTokens) {
  const Anthropic = require('@anthropic-ai/sdk');
  const client    = new Anthropic({ apiKey: backend.apiKey });
  const message   = await client.messages.create({
    model:      backend.model,
    max_tokens: maxTokens,
    messages:   [{ role: 'user', content: prompt }]
  });
  const text = message.content[0]?.text;
  if (!text) throw new Error('Anthropic returned an empty response.');
  return text;
}

async function _anthropicStream(backend, prompt, maxTokens, res) {
  const Anthropic = require('@anthropic-ai/sdk');
  const client    = new Anthropic({ apiKey: backend.apiKey });

  const stream = await client.messages.stream({
    model:      backend.model,
    max_tokens: maxTokens,
    messages:   [{ role: 'user', content: prompt }]
  });

  for await (const chunk of stream) {
    if (chunk.type === 'content_block_delta' && chunk.delta?.type === 'text_delta') {
      res.write(`data: ${JSON.stringify({ text: chunk.delta.text })}\n\n`);
    }
  }

  res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
  res.end();
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = { isConfigured, complete, streamToSSE, getBackend };
