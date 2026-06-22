/**
 * NFA Reseller API Proxy — Cloudflare Worker
 */

const NFA_ORIGIN = 'https://nfa-api.acode.ing';

// Leave empty to allow all origins.
const ALLOWED_ORIGINS = new Set(['*']);

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Panel-Auth',
    'Access-Control-Max-Age': '86400',
  };
}

function extractKeyStrings(data) {
  if (!data) return [];
  let arr = [];
  if (Array.isArray(data)) arr = data;
  else arr = data.keys || data.results || data.data || [];
  if (!Array.isArray(arr)) return [];
  return arr.map(item => {
    if (typeof item === 'string') return item;
    if (item && typeof item === 'object') return item.key || item.code || item.license || item.value || '';
    return String(item);
  }).filter(Boolean);
}

// Verify a SellAuth HMAC-SHA256 signature (hex) over the raw request body.
async function verifyHmacSha256(rawBody, signatureHex, secret) {
  try {
    if (!signatureHex || !secret) return false;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = await crypto.subtle.sign('HMAC', key, enc.encode(rawBody));
    const hex = [...new Uint8Array(mac)].map(b => b.toString(16).padStart(2, '0')).join('');
    if (hex.length !== signatureHex.length) return false;
    let diff = 0;
    for (let i = 0; i < hex.length; i++) diff |= hex.charCodeAt(i) ^ signatureHex.charCodeAt(i);
    return diff === 0;
  } catch (e) {
    return false;
  }
}

// Public webhook: mints license keys for one product and returns them as
// plain text, one key per line. Works as a simple token-protected URL and as a
// SellAuth Dynamic Delivery endpoint (POST + JSON body + HMAC signature).
async function handleWebhookKeys(request, env, url) {
  const headers = { 'Content-Type': 'text/plain; charset=utf-8', 'Access-Control-Allow-Origin': '*' };

  if (!env.WEBHOOK_TOKEN && !env.SELLAUTH_WEBHOOK_SECRET) {
    return new Response('Webhook disabled: set WEBHOOK_TOKEN or SELLAUTH_WEBHOOK_SECRET', { status: 503, headers });
  }

  const params = url.searchParams;

  // Read the raw body once (used for both signature verification and quantity).
  let rawBody = '';
  if (request.method === 'POST' || request.method === 'PUT') {
    rawBody = await request.text();
  }

  // Auth: accept a matching token (per-variant URL) OR a valid SellAuth signature.
  const token = params.get('token') || request.headers.get('X-Webhook-Token') || '';
  let authed = !!(env.WEBHOOK_TOKEN && token === env.WEBHOOK_TOKEN);
  if (!authed && env.SELLAUTH_WEBHOOK_SECRET) {
    const sig = request.headers.get('X-Signature') || '';
    authed = await verifyHmacSha256(rawBody, sig, env.SELLAUTH_WEBHOOK_SECRET);
  }
  if (!authed) {
    return new Response('Unauthorized', { status: 401, headers });
  }

  // Parse the SellAuth (or generic) JSON body if present.
  let body = null;
  if (rawBody) {
    try { body = JSON.parse(rawBody); } catch (e) { body = null; }
  }

  const type = params.get('type') || params.get('product') || params.get('account_type');
  if (!type) {
    return new Response('Missing required "type" parameter', { status: 400, headers });
  }

  // Quantity: query param first, else SellAuth's item.quantity, else body amount.
  let qty = parseInt(params.get('quantity') || params.get('qty') || params.get('amount') || '', 10);
  if ((!Number.isFinite(qty) || qty < 1) && body) {
    qty = parseInt((body.item && body.item.quantity) ?? body.quantity ?? body.amount ?? '1', 10);
  }
  if (!Number.isFinite(qty) || qty < 1) qty = 1;
  if (qty > 500) qty = 500;

  if (!env.NFA_API_KEY) {
    return new Response('Server misconfigured: NFA_API_KEY is not set', { status: 500, headers });
  }

  try {
    const res = await fetch(`${NFA_ORIGIN}/api/v1/create_keys`, {
      method: 'POST',
      headers: { 'X-API-Key': env.NFA_API_KEY, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ account_type: type, amount: qty }),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = (data && data.message) ? data.message : `Upstream error (HTTP ${res.status})`;
      return new Response(msg, { status: res.status, headers });
    }
    const keys = extractKeyStrings(data);
    if (!keys.length) {
      return new Response('No keys returned by upstream', { status: 502, headers });
    }
    return new Response(keys.join('\n') + '\n', { status: 200, headers });
  } catch (err) {
    return new Response('Webhook failed: ' + err.message, { status: 502, headers });
  }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const url = new URL(request.url);

    // --- Public per-product key webhook (plain text, one key per line) ---
    if (url.pathname === '/webhook/keys') {
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders(origin) });
      }
      return handleWebhookKeys(request, env, url);
    }

    // --- Serve Static Assets ---
    // In a worker with [assets] binding, assets are served natively if the request
    // doesn't hit a custom handler, or if we use env.ASSETS.fetch(request)
    if (!url.pathname.startsWith('/api/')) {
        return env.ASSETS.fetch(request);
    }

    // --- CORS preflight ---
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // --- Panel auth check ---
    if (env.PANEL_AUTH_TOKEN) {
      const isPublic = url.pathname.endsWith('/create_exe') || url.pathname.endsWith('/activate');
      if (!isPublic) {
        const token = request.headers.get('X-Panel-Auth') || '';
        if (token !== env.PANEL_AUTH_TOKEN) {
          return new Response(JSON.stringify({ status: 'error', message: 'Invalid panel authentication' }), {
              status: 403,
              headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) }
          });
        }
      }
    }

    // --- Build upstream request ---
    const upstream = new URL(url.pathname + url.search, NFA_ORIGIN);

    if (!env.NFA_API_KEY) {
      return new Response(JSON.stringify({ 
          status: 'error', 
          message: 'Server configuration error: NFA_API_KEY is not set in Cloudflare'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    const headers = new Headers();
    headers.set('X-API-Key', env.NFA_API_KEY);
    headers.set('Content-Type', 'application/json');
    headers.set('Accept', 'application/json');

    const init = {
      method: request.method,
      headers,
    };

    if (['POST', 'PUT', 'DELETE'].includes(request.method)) {
      const body = await request.text();
      if (body) init.body = body;
    }

    try {
      const response = await fetch(upstream.toString(), init);

      const responseHeaders = new Headers(response.headers);
      responseHeaders.delete('Server');
      responseHeaders.delete('X-Powered-By');
      const cors = corsHeaders(origin);
      for (const [k, v] of Object.entries(cors)) {
        responseHeaders.set(k, v);
      }

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (err) {
      return new Response(JSON.stringify({ status: 'error', message: 'Upstream request failed: ' + err.message }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }
  },
};
