// Optional AI assist (Settings → AI assist, off by default): grouping step 5 and product extraction only.
// The model receives one or two headlines, never inventory. Its answers only steer matching and grouping;
// the Fix field is always parser-sourced. With the flag off nothing here runs.
import { extractKeys } from '../public/engine.js';
import { http, secret } from './util.js';

export function aiAvailable(env, S) {
  if (!S.ai) return false;
  if ((S.aiProvider || 'workers-ai') === 'workers-ai') return !!env.AI;
  return !!(S.aiEndpoint && secret(env, 'env:AZURE_OPENAI_KEY'));
}

async function chat(env, S, prompt, fetchImpl) {
  const messages = [{ role: 'system', content: 'Reply with one JSON object only.' }, { role: 'user', content: prompt }];
  if ((S.aiProvider || 'workers-ai') === 'workers-ai') {
    const r = await env.AI.run(S.aiModel || '@cf/meta/llama-3.1-8b-instruct-fast', { messages, max_tokens: 60, temperature: 0 });
    return String(r?.response ?? '');
  }
  const url = `${S.aiEndpoint.replace(/\/+$/, '')}/openai/deployments/${encodeURIComponent(S.aiModel)}/chat/completions?api-version=2024-10-21`;
  const { res } = await http(url, { fetch: fetchImpl, method: 'POST', body: JSON.stringify({ messages, max_tokens: 60, temperature: 0 }), headers: { 'api-key': secret(env, 'env:AZURE_OPENAI_KEY'), 'content-type': 'application/json' } });
  if (!res.ok) throw new Error('AI ' + res.status);
  return String((await res.json()).choices?.[0]?.message?.content ?? '');
}
const obj = t => { const m = String(t).match(/\{[\s\S]*\}/); try { return m ? JSON.parse(m[0]) : null; } catch { return null; } };

// Input: two headlines. Output: { same, conf }.
export async function greyPair(env, S, a, b, fetchImpl) {
  const q = `Do these two security headlines describe the same real-world event?\nA: ${JSON.stringify(a)}\nB: ${JSON.stringify(b)}\nJSON: {"same": true|false, "confidence": 0..1}`;
  const j = obj(await chat(env, S, q, fetchImpl)) || {};
  return { same: j.same === true && (+j.confidence || 0) >= 0.6, conf: Math.max(0, Math.min(1, +j.confidence || 0)) };
}

// Input: one headline. The vendor/product text is mapped to keys locally against the alias table.
export async function extractProduct(env, S, headline, aliases, fetchImpl) {
  const q = `Which vendor and product does this security headline name?\nHeadline: ${JSON.stringify(headline)}\nJSON: {"vendor": "", "product": ""}`;
  const j = obj(await chat(env, S, q, fetchImpl)) || {};
  return extractKeys(`${j.vendor || ''} ${j.product || ''}`, aliases);
}
