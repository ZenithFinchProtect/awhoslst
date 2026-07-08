/**
 * NFA Reseller API Proxy — Cloudflare Worker
 */

const NFA_ORIGIN = 'https://nfa-api.acode.ing';

// Shown when a key is activated against a product that has no stock left.
const RESTOCK_MESSAGE = 'SELECTED NFA OUT OF STOCK — USE SAME KEY WHEN AVAILABLE';

// True when an upstream error means activation failed because there is no
// stock available to assign to the key (rather than an invalid key).
function isOutOfStock(message) {
  return /out\s*of\s*stock|no\s+stock|sold\s*out|restock|activation\s+not\s+found|not\s+activated/i.test(message || '');
}

// Leave empty to allow all origins.
const ALLOWED_ORIGINS = new Set(['*']);

// SellAuth Dynamic Delivery webhook path.
// Configure this URL in SellAuth: Product → Delivery → Dynamic.
const SELLAUTH_WEBHOOK_PATH = '/webhook/sellauth';

// reselling.pro dynamic-delivery webhook path (JSON body order payload).
// Configure this URL on the reselling.pro product's delivery settings.
const RESELLING_WEBHOOK_PATH = '/webhook/reselling';

// Token-authenticated key-delivery webhook (query-string style):
//   GET|POST /webhook/keys?type=<nfa_type>&token=<secret>&quantity=<n>
// This is the shape reselling.pro's delivery actually calls — the NFA account
// type is passed directly, so no name matching is needed. `token` must equal
// KEYS_WEBHOOK_TOKEN so the mint endpoint can't be abused.
const KEYS_WEBHOOK_PATH = '/webhook/keys';

// Stock Discord bot — config API + KV key.
const STOCK_BOT_PREFIX = '/api/stock-bot/';

// Cooldown between panel key generations (KV-backed).
const CREATE_KEYS_COOLDOWN_KEY = 'create_keys_last';
const CREATE_KEYS_COOLDOWN_MS = 3 * 60 * 1000;
const STOCK_BOT_CONFIG_KEY = 'config';

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Panel-Auth',
    'Access-Control-Max-Age': '86400',
  };
}

// Stock-only maintenance mode: when env.NFA_STOCK_ONLY === '1', only the
// stock endpoints may reach the NFA API. Delivery webhooks and the loader/
// activation endpoints return 503 (delivery platforms retry later), and the
// Discord stock-bot cron is paused. Used to bring services back one at a time
// after an NFA rate-limit block without immediately tripping it again.
function stockOnly(env) {
  return env.NFA_STOCK_ONLY === '1';
}

// Full pause: no NFA-bound traffic at all (stock included). Toggle with
// `wrangler secret put NFA_PAUSED` ("1" = paused); takes effect immediately.
function fullyPaused(env) {
  return env.NFA_PAUSED === '1';
}

function pausedResponse(origin) {
  return new Response(JSON.stringify({
    status: 'error',
    message: 'Temporarily unavailable: maintenance in progress',
  }), {
    status: 503,
    headers: { 'Content-Type': 'application/json', 'Retry-After': '600', ...corsHeaders(origin) },
  });
}

function stockOnlyResponse(origin) {
  return new Response(JSON.stringify({
    status: 'error',
    message: 'Temporarily unavailable: stock-only maintenance mode is enabled',
  }), {
    status: 503,
    headers: { 'Content-Type': 'application/json', 'Retry-After': '600', ...corsHeaders(origin) },
  });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const url = new URL(request.url);

    // Full pause: nothing may reach the NFA API (webhooks get 503 so the
    // platforms retry later).
    if (fullyPaused(env) && (url.pathname.startsWith('/api/v1/') || url.pathname.startsWith('/webhook/'))
        && url.pathname !== '/api/v1/panel-auth') {
      return pausedResponse(origin);
    }

    // --- SellAuth Dynamic Delivery webhook ---
    if (url.pathname === SELLAUTH_WEBHOOK_PATH) {
      if (stockOnly(env)) return stockOnlyResponse(origin);
      return handleSellAuthWebhook(request, env);
    }

    // --- reselling.pro dynamic-delivery webhook (JSON body) ---
    if (url.pathname === RESELLING_WEBHOOK_PATH) {
      if (stockOnly(env)) return stockOnlyResponse(origin);
      return handleResellingWebhook(request, env);
    }

    // --- Token-authenticated key delivery (query-string) ---
    if (url.pathname === KEYS_WEBHOOK_PATH) {
      if (stockOnly(env)) return stockOnlyResponse(origin);
      return handleKeysWebhook(request, env, url);
    }

    // --- Stock Discord bot config/control API ---
    if (url.pathname.startsWith(STOCK_BOT_PREFIX)) {
      return handleStockBotApi(request, env, url);
    }

    // --- Panel auth endpoint: verify password server-side ---
    if (url.pathname === '/api/v1/panel-auth') {
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders(origin) });
      }
      return handlePanelAuth(request, env, origin);
    }

    // --- Combined loader endpoint: activate + download in one request ---
    if (url.pathname === '/api/v1/loader') {
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders(origin) });
      }
      if (stockOnly(env)) return stockOnlyResponse(origin);
      return handleLoaderEndpoint(request, env, origin);
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

    // In stock-only mode, only the stock proxy path may reach the NFA API.
    if (stockOnly(env) && url.pathname !== '/api/v1/stock') {
      return stockOnlyResponse(origin);
    }

    // Serve proxied stock requests from the short-lived cache so panel traffic
    // doesn't hit the NFA API on every request.
    if (request.method === 'GET' && url.pathname === '/api/v1/stock') {
      try {
        const stock = await fetchNfaStock(env);
        return new Response(JSON.stringify({ status: 'success', stock }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
        });
      } catch (err) {
        return new Response(JSON.stringify({ status: 'error', message: err.message }), {
          status: 502,
          headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
        });
      }
    }

    // The generic proxy attaches the secret NFA key, so it must not be an open
    // relay: anyone hammering it would look like us spamming the NFA API (and
    // could mint keys). Key-holder endpoints stay public; everything else
    // requires the panel password via X-Panel-Auth.
    const PUBLIC_PROXY_PATHS = new Set(['/api/v1/activate', '/api/v1/create_exe']);
    if (!PUBLIC_PROXY_PATHS.has(url.pathname)) {
      const token = (request.headers.get('X-Panel-Auth') || '').trim();
      const expected = env.PANEL_PASSWORD || 'NordicNFA2026';
      if (token !== expected) {
        return new Response(JSON.stringify({ status: 'error', message: 'Invalid panel authentication' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
        });
      }
    }

    // Key generation cooldown: at most one create_keys call every 3 minutes,
    // tracked in KV so it holds across isolates.
    if (url.pathname === '/api/v1/create_keys' && stockBotConfigured(env)) {
      const last = Number(await env.STOCK_BOT.get(CREATE_KEYS_COOLDOWN_KEY)) || 0;
      const elapsed = Date.now() - last;
      if (elapsed < CREATE_KEYS_COOLDOWN_MS) {
        const waitSec = Math.ceil((CREATE_KEYS_COOLDOWN_MS - elapsed) / 1000);
        return new Response(JSON.stringify({
          status: 'error',
          message: `Key generation is on cooldown — try again in ${waitSec}s`,
        }), {
          status: 429,
          headers: { 'Content-Type': 'application/json', 'Retry-After': String(waitSec), ...corsHeaders(origin) },
        });
      }
      await env.STOCK_BOT.put(CREATE_KEYS_COOLDOWN_KEY, String(Date.now()));
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

  // Cron trigger — fires every minute (see wrangler.toml). Posts the stock
  // embed to Discord only when the configured interval has elapsed.
  async scheduled(event, env, ctx) {
    if (fullyPaused(env) || stockOnly(env)) return;
    ctx.waitUntil(runStockBot(env, { force: false }));
  },
};

// ───────────────────────────────────────────────────────────────────────────
//  Combined Loader Endpoint — /api/v1/loader
//
//  Merges the activate + create_exe dance into a single request. The browser
//  makes ONE call; the worker handles the NFA round-trips server-side (≈1 ms
// ───────────────────────────────────────────────────────────────────────────
//  Panel Auth — server-side password verification so the password never
//  appears in client-side source code.
// ───────────────────────────────────────────────────────────────────────────

async function handlePanelAuth(request, env, origin) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ ok: false, error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ ok: false, error: 'Invalid JSON' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  const password = (body.password || '').trim();
  const expected = (env.PANEL_PASSWORD || 'NordicNFA2026');

  if (!password || password !== expected) {
    return new Response(JSON.stringify({ ok: false, error: 'Incorrect password' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

//  RTT vs hundreds of ms from the end-user). Returns the EXE as a binary
//  download directly — no base64 JSON overhead.
// ───────────────────────────────────────────────────────────────────────────

async function handleLoaderEndpoint(request, env, origin) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ status: 'error', message: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  if (!env.NFA_API_KEY) {
    return new Response(JSON.stringify({ status: 'error', message: 'Server configuration error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ status: 'error', message: 'Invalid JSON body' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  const key = body && body.activation_key;
  if (!key) {
    return new Response(JSON.stringify({ status: 'error', message: 'activation_key is required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }

  const nfaHeaders = {
    'X-API-Key': env.NFA_API_KEY,
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };

  const jsonErr = (status, message) => new Response(
    JSON.stringify({ status: 'error', message }),
    { status, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) } }
  );

  // Step 1: Try create_exe — fast path for already-activated keys.
  let exeData;
  try {
    const res = await fetch(`${NFA_ORIGIN}/api/v1/create_exe`, {
      method: 'POST',
      headers: nfaHeaders,
      body: JSON.stringify({ activation_key: key }),
    });
    const data = await res.json();

    if (res.ok && data.exe_base64) {
      // Key already activated — return binary immediately.
      exeData = data;
    } else if (/activation not found/i.test(data.message || '')) {
      // Key not activated yet — activate it.
      const actRes = await fetch(`${NFA_ORIGIN}/api/v1/activate`, {
        method: 'POST',
        headers: nfaHeaders,
        body: JSON.stringify({ activation_key: key }),
      });
      const actData = await actRes.json();

      if (!actRes.ok) {
        const m = actData.message || 'Activation failed';
        return jsonErr(actRes.status, isOutOfStock(m) ? RESTOCK_MESSAGE : m);
      }

      // Some NFA versions return the EXE directly from activate.
      if (actData.exe_base64) {
        exeData = actData;
      } else {
        // Activation succeeded but no EXE — build it now.
        const exeRes = await fetch(`${NFA_ORIGIN}/api/v1/create_exe`, {
          method: 'POST',
          headers: nfaHeaders,
          body: JSON.stringify({ activation_key: key }),
        });
        const exeJson = await exeRes.json();
        if (!exeRes.ok || !exeJson.exe_base64) {
          const s = exeRes.ok ? 422 : (exeRes.status || 500);
          const m = exeJson.message || 'Failed to build loader';
          return jsonErr(s, isOutOfStock(m) ? RESTOCK_MESSAGE : m);
        }
        exeData = exeJson;
      }
    } else {
      // Unexpected error from create_exe.
      // Force non-2xx so the frontend shows an error instead of downloading the JSON.
      const errStatus = res.ok ? 422 : res.status;
      return jsonErr(errStatus, data.message || 'Failed to build loader');
    }
  } catch (err) {
    return jsonErr(502, 'Upstream request failed: ' + err.message);
  }

  // Decode base64 → binary and stream as a file download.
  const binary = Uint8Array.from(atob(exeData.exe_base64), c => c.charCodeAt(0));
  const filename = exeData.exe_filename || 'loader.exe';

  return new Response(binary, {
    status: 200,
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': String(binary.length),
      ...corsHeaders(origin),
    },
  });
}

// ───────────────────────────────────────────────────────────────────────────
//  SellAuth Dynamic Delivery
//  https://docs.sellauth.com/guides/dynamic-delivery
//
//  On checkout, SellAuth POSTs one request per invoice item. We verify the
//  HMAC-SHA256 signature, mint NFA key(s) for the purchased product, and return
//  them as plain text (one deliverable per line). HTTP 200 = delivered.
// ───────────────────────────────────────────────────────────────────────────

function plain(status, text) {
  return new Response(text, {
    status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
}

// Constant-time string comparison.
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Cache of valid NFA account-type keys (fetched from the upstream accounts list).
// Module scope persists across requests in the same isolate; a short TTL keeps it
// fresh without re-fetching on every webhook (which would add API calls).
let _validTypesCache = { time: 0, types: null };
const VALID_TYPES_TTL = 5 * 60 * 1000;

async function getValidAccountTypes(env) {
  const now = Date.now();
  if (_validTypesCache.types && now - _validTypesCache.time < VALID_TYPES_TTL) {
    return _validTypesCache.types;
  }
  try {
    const res = await fetch(`${NFA_ORIGIN}/api/v1/accounts`, {
      headers: { 'X-API-Key': env.NFA_API_KEY, Accept: 'application/json' },
    });
    if (!res.ok) return _validTypesCache.types || [];
    const data = await res.json();
    const accounts = data && data.accounts ? data.accounts : {};
    const types = Object.keys(accounts);
    if (types.length) _validTypesCache = { time: now, types };
    return types;
  } catch {
    return _validTypesCache.types || [];
  }
}

// Canonicalize individual tokens so the same concept tokenizes identically on both
// the SellAuth name and the NFA key side, smoothing over NFA's naming quirks:
//   "h"/"hr"/"hrs" -> "hours"  (some keys use "1000h", others "..._hours")
//   "inventory"    -> "inv"    (cs2_*_inventory vs rust_premium_*_inv)
//   "knives"/etc.  -> "knifes" (NFA spells it "knifes" in cs2_knifes_gloves)
function canonToken(t) {
  if (t === 'hrs' || t === 'hr' || t === 'h') return 'hours';
  if (t === 'inventory' || t === 'inventories' || t === 'inv') return 'inv';
  if (t === 'knives' || t === 'knive' || t === 'knife' || t === 'knifes') return 'knifes';
  return t;
}

// Tokenize a free-form name into a Set of canonical lowercase tokens. Applied
// identically to SellAuth names and to NFA keys so they tokenize consistently:
//   "Rust Temporary Account (0-250 Hours)" -> {rust,temporary,account,0,250,hours}
//   "rust_0_250_hours"                      -> {rust,0,250,hours}
// "+" becomes "plus" ("7000+ Hours" -> rust_7000_plus_hours), an "Nd"/"N days"
// suffix is split to "N d" (so "5 days" matches "..._5d"), and letter<->digit
// boundaries are split ("10medals" -> "10","medals"; "1000h" -> "1000","hours").
function nameTokens(str) {
  const norm = String(str || '')
    .toLowerCase()
    .replace(/\+/g, ' plus ')
    .replace(/(\d+)\s*d(?:ays?)?\b/g, '$1 d ')
    .replace(/([a-z])([0-9])/g, '$1 $2')
    .replace(/([0-9])([a-z])/g, '$1 $2')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
  return new Set(norm.split(/\s+/).filter(Boolean).map(canonToken));
}

// Match a SellAuth product/variant name to a valid NFA account type.
// Conservative by design: a type is only chosen when ALL of its tokens appear in
// the item's tokens AND it strictly out-scores every other candidate (by token
// count). On ambiguity or no match it returns null so the webhook fails safely
// instead of minting a wrong (possibly pricier) account.
function matchAccountType(text, validTypes) {
  const tokens = nameTokens(text);
  if (!tokens.size) return null;

  let best = null;
  let bestScore = 0;
  let tie = false;

  for (const type of validTypes) {
    const typeTokens = [...nameTokens(type)];
    if (!typeTokens.length || !typeTokens.every((t) => tokens.has(t))) continue;
    const score = typeTokens.length;
    if (score > bestScore) {
      bestScore = score;
      best = type;
      tie = false;
    } else if (score === bestScore) {
      tie = true;
    }
  }

  return best && !tie ? best : null;
}

// Decide which NFA account type to mint for a delivery item (SellAuth or
// reselling.pro). Priority:
//   1. A product map env (JSON) keyed by variant_id, then product_id.
//   2. A custom field literally named "account_type".
//   3. Automatic match of the variant/product name against the live NFA type list.
//   4. The raw variant name, then the product name.
// `mapJson` is the raw JSON string of the per-platform product map
// (SELLAUTH_PRODUCT_MAP by default, RESELLING_PRODUCT_MAP for reselling.pro).
async function resolveAccountType(item, env, mapJson = env.SELLAUTH_PRODUCT_MAP) {
  const product = item.product || {};
  const variant = item.variant || {};

  if (mapJson) {
    let map = null;
    try {
      map = JSON.parse(mapJson);
    } catch {
      map = null;
    }
    if (map) {
      const variantKey = item.variant_id != null ? String(item.variant_id) : null;
      const productKey = item.product_id != null ? String(item.product_id) : null;
      if (variantKey && map[variantKey]) return map[variantKey];
      if (productKey && map[productKey]) return map[productKey];
    }
  }

  const fields = item.custom_fields || {};
  for (const [name, value] of Object.entries(fields)) {
    if (name.trim().toLowerCase() === 'account_type' && value) return String(value);
  }

  const validTypes = await getValidAccountTypes(env);
  if (validTypes.length) {
    const matched = matchAccountType(`${product.name || ''} ${variant.name || ''}`, validTypes);
    if (matched) return matched;
  }

  if (variant.name) return variant.name;
  if (product.name) return product.name;
  return null;
}

function extractKeys(data) {
  if (!data || !Array.isArray(data.keys)) return [];
  return data.keys
    .map((k) => {
      if (typeof k === 'string') return k;
      if (k && typeof k === 'object') return k.key || k.activation_key || k.activationKey || '';
      return '';
    })
    .filter(Boolean);
}

async function handleSellAuthWebhook(request, env) {
  if (request.method !== 'POST') {
    return plain(405, 'Method not allowed');
  }

  // Raw body is required for signature verification — read it once as text.
  const rawBody = await request.text();

  // --- Signature verification (HMAC-SHA256 over the raw body) ---
  if (env.SELLAUTH_WEBHOOK_SECRET) {
    const provided = request.headers.get('X-Signature') || '';
    const expected = await hmacSha256Hex(env.SELLAUTH_WEBHOOK_SECRET, rawBody);
    if (!provided || !timingSafeEqual(provided, expected)) {
      return plain(401, 'Invalid signature');
    }
  }

  if (!env.NFA_API_KEY) {
    // Retryable: server is misconfigured, don't fail the customer's item yet.
    return plain(500, 'Server configuration error: NFA_API_KEY is not set');
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return plain(400, 'Invalid JSON body');
  }

  const item = payload.item || {};
  const accountType = await resolveAccountType(item, env);
  if (!accountType) {
    return plain(400, 'Unable to determine account type for this product. Configure SELLAUTH_PRODUCT_MAP or set the variant/product name to a valid NFA account type.');
  }

  const amount = Number(item.quantity) > 0 ? Number(item.quantity) : 1;
  return deliverKeys(env, accountType, amount);
}

// Mint `amount` keys of `accountType` from NFA and return them as the webhook
// response (one deliverable per line on HTTP 200). Upstream 5xx maps to a
// retryable 502; other failures to a non-retryable 400.
async function deliverKeys(env, accountType, amount) {
  let nfaResponse;
  try {
    nfaResponse = await fetch(`${NFA_ORIGIN}/api/v1/create_keys`, {
      method: 'POST',
      headers: {
        'X-API-Key': env.NFA_API_KEY,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ account_type: accountType, amount }),
    });
  } catch (err) {
    return plain(502, 'Upstream request failed: ' + err.message);
  }

  let data = null;
  const text = await nfaResponse.text();
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (!nfaResponse.ok) {
    const message = (data && data.message) || text || 'Failed to create keys';
    const status = nfaResponse.status >= 500 ? 502 : 400;
    return plain(status, message);
  }

  const keys = extractKeys(data);
  if (!keys.length) {
    return plain(400, (data && data.message) || 'No keys were generated for this order.');
  }

  return plain(200, keys.join('\n'));
}

// Normalize a dynamic-delivery payload into the { product, variant, product_id,
// variant_id, quantity, custom_fields } shape resolveAccountType expects.
// Tolerant of the field naming used by reselling.pro / SellAuth / Komerza /
// Shoppex / Sell.app (camelCase + snake_case, nested item/line_item/order.items).
function normalizeDeliveryItem(payload) {
  const p = payload || {};
  const item = p.item || {};
  const li = p.line_item || p.lineItem || {};
  const orderItem =
    (p.order && Array.isArray(p.order.items) && p.order.items[0]) ||
    (Array.isArray(p.items) && p.items[0]) ||
    {};
  const product = item.product || p.product || {};
  const variant = item.variant || p.variant || {};

  const productName =
    product.name || product.title ||
    p.productName || p.productTitle || p.product_title ||
    li.product_title || li.productName ||
    orderItem.productName || orderItem.product_name || orderItem.name || '';
  const variantName =
    variant.name || variant.title ||
    p.variantName || p.variantTitle || p.variant_title ||
    li.variant_title || li.variantName ||
    orderItem.variantName || orderItem.variant_name || '';

  const firstDefined = (...vals) => vals.find((v) => v != null && v !== '');
  const productId = firstDefined(
    item.product_id, p.productId, p.product_id, product.id,
    li.product_id, orderItem.product_id, orderItem.productId,
  );
  const variantId = firstDefined(
    item.variant_id, p.variantId, p.variant_id, variant.id,
    li.variant_id, orderItem.variant_id, orderItem.variantId,
  );
  const quantity =
    Number(item.quantity || p.quantity || li.quantity || orderItem.quantity || 1) || 1;
  const custom_fields =
    item.custom_fields || p.custom_fields || p.customFields || li.custom_fields || {};

  return {
    product_id: productId != null ? productId : null,
    variant_id: variantId != null ? variantId : null,
    product: { name: productName },
    variant: { name: variantName },
    quantity,
    custom_fields,
  };
}

// Token-authenticated, query-string key delivery used by reselling.pro:
//   GET|POST /webhook/keys?type=<type>&token=<secret>&quantity=<n>
// `type` may be an exact NFA type or a display name (matched against the live
// type list). `quantity` defaults to 1. Returns the minted keys as plain text.
async function handleKeysWebhook(request, env, url) {
  if (request.method !== 'GET' && request.method !== 'POST') {
    return plain(405, 'Method not allowed');
  }

  const params = url.searchParams;
  const token = params.get('token') || request.headers.get('X-Token') || '';

  if (!env.KEYS_WEBHOOK_TOKEN) {
    return plain(500, 'Server configuration error: KEYS_WEBHOOK_TOKEN is not set');
  }
  if (!token || !timingSafeEqual(token, env.KEYS_WEBHOOK_TOKEN)) {
    return plain(401, 'Invalid token');
  }
  if (!env.NFA_API_KEY) {
    return plain(500, 'Server configuration error: NFA_API_KEY is not set');
  }

  const rawType = (params.get('type') || params.get('account_type') || '').trim();
  if (!rawType) {
    return plain(400, 'Missing type');
  }
  const quantity = Number(params.get('quantity')) > 0 ? Number(params.get('quantity')) : 1;

  // Accept an exact NFA type; otherwise try to match a display name.
  let accountType = rawType;
  const validTypes = await getValidAccountTypes(env);
  if (validTypes.length && !validTypes.includes(rawType)) {
    const matched = matchAccountType(rawType, validTypes);
    if (matched) accountType = matched;
    else return plain(400, `Account type '${rawType}' not found`);
  }

  console.log('keys webhook', JSON.stringify({ type: rawType, resolved: accountType, quantity }));

  return deliverKeys(env, accountType, quantity);
}

async function handleResellingWebhook(request, env) {
  if (request.method !== 'POST') {
    return plain(405, 'Method not allowed');
  }

  const rawBody = await request.text();

  // Optional signature verification (HMAC-SHA256 over the raw body). Only
  // enforced when RESELLING_WEBHOOK_SECRET is set; the header name varies by
  // platform so a few common ones are accepted.
  if (env.RESELLING_WEBHOOK_SECRET) {
    const provided =
      request.headers.get('X-Signature') ||
      request.headers.get('X-Webhook-Signature') ||
      request.headers.get('X-Reselling-Signature') ||
      '';
    const expected = await hmacSha256Hex(env.RESELLING_WEBHOOK_SECRET, rawBody);
    if (!provided || !timingSafeEqual(provided, expected)) {
      return plain(401, 'Invalid signature');
    }
  }

  if (!env.NFA_API_KEY) {
    return plain(500, 'Server configuration error: NFA_API_KEY is not set');
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return plain(400, 'Invalid JSON body');
  }

  const item = normalizeDeliveryItem(payload);
  const accountType = await resolveAccountType(item, env, env.RESELLING_PRODUCT_MAP);

  // Observability (no customer PII): payload shape + what we resolved.
  console.log('reselling webhook', JSON.stringify({
    topKeys: Object.keys(payload || {}),
    product: item.product.name,
    variant: item.variant.name,
    product_id: item.product_id,
    variant_id: item.variant_id,
    quantity: item.quantity,
    resolved: accountType,
  }));

  if (!accountType) {
    return plain(400, 'Unable to determine account type for this product. Configure RESELLING_PRODUCT_MAP or name the reselling.pro product to match a valid NFA account type.');
  }

  const amount = Number(item.quantity) > 0 ? Number(item.quantity) : 1;
  return deliverKeys(env, accountType, amount);
}

// ───────────────────────────────────────────────────────────────────────────
//  Stock Discord bot
//
//  A scheduled worker posts a "Stock Update Alert" embed (matching the design
//  in the panel) to a Discord webhook. Everything is configured from the panel
//  and stored in the STOCK_BOT KV namespace.
// ───────────────────────────────────────────────────────────────────────────

const DEFAULT_STOCK_CONFIG = {
  enabled: false,
  // Legacy single webhook (migrated into `webhooks` on read). Kept for back-compat.
  webhookUrl: '',
  // One entry per reseller destination: { id, name, url, enabled }.
  webhooks: [],
  intervalMinutes: 60,
  username: 'Stock alert',
  avatarUrl: '',
  title: '📊 Stock Update Alert',
  note: 'If the stock exceeds 5, it will be displayed as 5',
  cap: 5, // 0 / null = no cap
  color: 3447003, // Discord blurple-ish blue
  showTimestamp: true,
  groups: [
    {
      title: 'CS2',
      emoji: '🔫',
      rows: [
        { label: 'Prime', key: 'cs2_prime' },
        { label: 'Prime · 15+d offline', key: 'cs2_prime_inactive' },
        { label: 'Premier', key: 'cs2_premier' },
        { label: 'Premier · 15+d offline', key: 'cs2_premier_inactive' },
        { label: '4+ medals', key: 'cs2_4medals' },
        { label: '4+ medals · 15+d offline', key: 'cs2_4medals_inactive' },
        { label: '10+ medals', key: 'cs2_10medals' },
        { label: '10+ medals · 15+d offline', key: 'cs2_10medals_inactive' },
        { label: '10–15k ELO', key: 'cs2_10_15k_elo' },
        { label: '15–20k ELO', key: 'cs2_15_20k_elo' },
        { label: '20–30k ELO', key: 'cs2_20_30k_elo' },
        { label: '5k+ ELO', key: 'cs2_5k_last_season' },
        { label: '10k+ ELO', key: 'cs2_10k_last_season' },
        { label: '15k+ ELO', key: 'cs2_15k_last_season' },
        { label: '20k+ ELO', key: 'cs2_20k_last_season' },
        { label: 'Knifes / Gloves', key: 'cs2_knifes_gloves' },
        { label: 'Inventory $500+', key: 'cs2_500_inv' },
        { label: 'Inventory $1000+', key: 'cs2_1000_inv' },
      ],
    },
    {
      title: 'Rust',
      emoji: '🪓',
      rows: [
        { label: 'Premium', key: 'rust_premium' },
        { label: 'Premium · 5+d offline', key: 'rust_premium_inactive_5d' },
        { label: 'Premium · 15+d offline', key: 'rust_premium_inactive_15d' },
        { label: 'Premium · 500+ h', key: 'rust_premium_500_hours' },
        { label: 'Premium · 1000+ h', key: 'rust_premium_1000_hours' },
        { label: 'Premium · inventory $50+', key: 'rust_premium_50_inv' },
        { label: 'Premium · inventory $100+', key: 'rust_premium_100_inv' },
        { label: '0-250 h', key: 'rust_0_250_hours' },
        { label: '250–500 h', key: 'rust_250_500_hours' },
        { label: '500–1000 h', key: 'rust_500_1000_hours' },
        { label: '1000–2000 h', key: 'rust_1000_2000_hours' },
        { label: '2000–3000 h', key: 'rust_2000_3000_hours' },
        { label: '3000–7000 h', key: 'rust_3000_7000_hours' },
        { label: '7000+ h', key: 'rust_7000_plus_hours' },
        { label: '5+d offline', key: 'rust_inactive_5d' },
        { label: '5+d offline · 500+ h', key: 'rust_inactive_5d_500_hours' },
        { label: '5+d offline · 1000+ h', key: 'rust_inactive_5d_1000_hours' },
        { label: '15+d offline', key: 'rust_inactive_15d' },
        { label: '15+d offline · 500+ h', key: 'rust_inactive_15d_500_hours' },
        { label: '15+d offline · 1000+ h', key: 'rust_inactive_15d_1000_hours' },
      ],
    },
    {
      title: 'Arc Raiders',
      emoji: '🛸',
      rows: [
        { label: '0–99 h', key: 'arc_0_99_hours' },
        { label: '100–200 h', key: 'arc_100_200_hours' },
        { label: '200+ h', key: 'arc_200_plus_hours' },
        { label: '15+d offline · 0–99 h', key: 'arc_inactive_15d_0_99_hours' },
        { label: '15+d offline · 100–200 h', key: 'arc_inactive_15d_100_200_hours' },
        { label: '15+d offline · 200+ h', key: 'arc_inactive_15d_200_plus_hours' },
      ],
    },
    {
      title: 'Battlefield 6',
      emoji: '🎖️',
      rows: [
        { label: 'Random', key: 'battlefield_6' },
      ],
    },
    {
      title: 'DayZ',
      emoji: '🧟',
      rows: [
        { label: 'Random', key: 'dayz' },
        { label: '500+ h', key: 'dayz_500_hours' },
        { label: '1000+ h', key: 'dayz_1000_hours' },
        { label: '15+d offline', key: 'dayz_inactive' },
      ],
    },
    {
      title: 'Escape from Tarkov',
      emoji: '🎯',
      rows: [
        { label: 'Random', key: 'escape_from_tarkov' },
      ],
    },
  ],
  lastSentAt: 0,
  lastAttemptAt: 0,
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Panel-Auth',
    },
  });
}

function stockBotConfigured(env) {
  return env.STOCK_BOT && typeof env.STOCK_BOT.get === 'function';
}

async function getStockConfig(env) {
  if (!stockBotConfigured(env)) return { ...DEFAULT_STOCK_CONFIG };
  const raw = await env.STOCK_BOT.get(STOCK_BOT_CONFIG_KEY);
  if (!raw) return { ...DEFAULT_STOCK_CONFIG };
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ...DEFAULT_STOCK_CONFIG };
  }
  const cfg = { ...DEFAULT_STOCK_CONFIG, ...parsed };
  // Migrate a legacy single webhook into the webhooks[] list.
  if (!Array.isArray(cfg.webhooks)) cfg.webhooks = [];
  if (!cfg.webhooks.length && cfg.webhookUrl) {
    cfg.webhooks = [{ id: 'legacy', name: 'Default', url: cfg.webhookUrl, enabled: true }];
  }
  cfg.webhookUrl = '';
  return cfg;
}

function newWebhookId() {
  try {
    return crypto.randomUUID();
  } catch {
    return 'wh_' + Math.random().toString(36).slice(2) + Date.now().toString(36);
  }
}

async function saveStockConfig(env, config) {
  await env.STOCK_BOT.put(STOCK_BOT_CONFIG_KEY, JSON.stringify(config));
}

// Sanitize/normalize a config object coming from the panel before saving.
function sanitizeStockConfig(input, previous) {
  const cfg = { ...DEFAULT_STOCK_CONFIG, ...previous };
  if (typeof input.enabled === 'boolean') cfg.enabled = input.enabled;

  // Reseller webhooks. Each entry: { id, name, url, enabled }. A blank url on an
  // existing entry (matched by id) keeps the stored url — so the masked panel
  // never wipes a webhook it can't read back.
  if (Array.isArray(input.webhooks)) {
    const prevById = new Map((previous && previous.webhooks ? previous.webhooks : []).map((w) => [w.id, w]));
    cfg.webhooks = input.webhooks
      .map((w) => {
        const id = typeof w.id === 'string' && w.id ? w.id : newWebhookId();
        const incomingUrl = typeof w.url === 'string' ? w.url.trim() : '';
        const prev = prevById.get(id);
        const url = incomingUrl || (prev ? prev.url : '');
        return {
          id,
          name: typeof w.name === 'string' ? w.name.slice(0, 80) : '',
          url,
          enabled: typeof w.enabled === 'boolean' ? w.enabled : true,
        };
      })
      .filter((w) => w.url || w.name);
  }
  if (input.intervalMinutes != null) {
    const n = Math.round(Number(input.intervalMinutes));
    cfg.intervalMinutes = Number.isFinite(n) && n >= 1 ? n : DEFAULT_STOCK_CONFIG.intervalMinutes;
  }
  if (typeof input.username === 'string') cfg.username = input.username.slice(0, 80);
  if (typeof input.avatarUrl === 'string') cfg.avatarUrl = input.avatarUrl.trim();
  if (typeof input.title === 'string') cfg.title = input.title.slice(0, 256);
  if (typeof input.note === 'string') cfg.note = input.note.slice(0, 2048);
  if (input.cap != null) {
    const c = Math.round(Number(input.cap));
    cfg.cap = Number.isFinite(c) && c > 0 ? c : 0;
  }
  if (input.color != null) {
    const col = Math.round(Number(input.color));
    if (Number.isFinite(col) && col >= 0 && col <= 0xffffff) cfg.color = col;
  }
  if (typeof input.showTimestamp === 'boolean') cfg.showTimestamp = input.showTimestamp;
  if (Array.isArray(input.groups)) {
    cfg.groups = input.groups
      .map((g) => ({
        title: typeof g.title === 'string' ? g.title.slice(0, 256) : '',
        emoji: typeof g.emoji === 'string' ? g.emoji.slice(0, 32) : '',
        rows: Array.isArray(g.rows)
          ? g.rows
              .map((r) => ({
                label: typeof r.label === 'string' ? r.label.slice(0, 200) : '',
                key: typeof r.key === 'string' ? r.key : '',
              }))
              .filter((r) => r.key || r.label)
          : [],
      }))
      .filter((g) => g.title || g.rows.length);
  }
  return cfg;
}

// Return the config with every webhook URL masked, so an open panel never
// exposes the Discord webhooks (credentials) to the public.
function maskStockConfig(cfg) {
  const masked = { ...cfg, webhookUrl: '' };
  masked.webhooks = (cfg.webhooks || []).map((w) => ({
    id: w.id,
    name: w.name || '',
    enabled: w.enabled !== false,
    url: '',
    urlSet: !!w.url,
    urlHint: w.url ? '…' + w.url.slice(-6) : '',
  }));
  return masked;
}

// NOTE: these endpoints are intentionally open, matching the rest of the panel
// (the password gate was removed). The webhook is masked on read and preserved
// when saved blank, so it isn't publicly readable or wiped by accident.
async function handleStockBotApi(request, env, url) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(null) });
  }

  if (!stockBotConfigured(env)) {
    return jsonResponse({
      status: 'error',
      message: 'STOCK_BOT KV namespace is not bound. Create it and set its id in wrangler.toml.',
    }, 500);
  }

  const action = url.pathname.slice(STOCK_BOT_PREFIX.length).replace(/\/+$/, '');

  // GET config
  if (action === 'config' && request.method === 'GET') {
    const cfg = await getStockConfig(env);
    return jsonResponse({ status: 'ok', config: maskStockConfig(cfg) });
  }

  // POST config — save
  if (action === 'config' && request.method === 'POST') {
    let input;
    try {
      input = await request.json();
    } catch {
      return jsonResponse({ status: 'error', message: 'Invalid JSON body' }, 400);
    }
    const previous = await getStockConfig(env);
    const cfg = sanitizeStockConfig(input, previous);
    await saveStockConfig(env, cfg);
    return jsonResponse({ status: 'ok', config: maskStockConfig(cfg) });
  }

  // POST send — send immediately (test / manual), ignoring the interval gate.
  if (action === 'send' && request.method === 'POST') {
    const result = await runStockBot(env, { force: true });
    const status = result.error ? 502 : 200;
    return jsonResponse({ status: result.error ? 'error' : 'ok', ...result }, status);
  }

  return jsonResponse({ status: 'error', message: 'Unknown stock-bot action' }, 404);
}

// Short-lived cache of the NFA stock map, so bursts of requests (panel
// buttons, cron retries) don't each hit the NFA API and trip its rate limit.
let _stockCache = { time: 0, stock: null };
const STOCK_CACHE_TTL = 60 * 1000;

// All stock reads go through the cached stock site rather than the NFA API
// directly, so the whole setup makes at most one stock call to NFA at a time.
const STOCK_SOURCE = 'https://stock.nfaccount.com/api/v1/stock';

// Fetch the live stock map from the cached stock site.
async function fetchNfaStock(env) {
  const now = Date.now();
  if (_stockCache.stock && now - _stockCache.time < STOCK_CACHE_TTL) {
    return _stockCache.stock;
  }
  const res = await fetch(STOCK_SOURCE, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
    },
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) {
    const msg = (data && data.message) || text || `HTTP ${res.status}`;
    throw new Error('Failed to fetch stock: ' + msg);
  }
  const stock = (data && data.stock) || {};
  _stockCache = { time: now, stock };
  return stock;
}

// Resolve a stock count for a key, with exact then case-insensitive matching.
function lookupStock(stock, key) {
  if (key in stock) return Number(stock[key]) || 0;
  const wanted = String(key).trim().toLowerCase();
  for (const [k, v] of Object.entries(stock)) {
    if (k.trim().toLowerCase() === wanted) return Number(v) || 0;
  }
  return 0;
}

function displayCount(count, cap) {
  return cap && cap > 0 && count > cap ? cap : count;
}

// Build the Discord embed payload from config + live stock.
function buildStockEmbed(config, stock) {
  const fields = [];
  for (const group of config.groups || []) {
    const lines = (group.rows || []).map((row) => {
      const n = displayCount(lookupStock(stock, row.key), config.cap);
      const label = row.label || row.key;
      return `${label}: **Stock: ${n}**`;
    });
    const name = `${group.emoji ? group.emoji + ' ' : ''}${group.title || '\u200b'}`.slice(0, 256);
    fields.push({
      name,
      value: (lines.join('\n') || '\u200b').slice(0, 1024),
      inline: false,
    });
  }

  const embed = {
    title: config.title || 'Stock Update Alert',
    color: config.color ?? DEFAULT_STOCK_CONFIG.color,
    fields: fields.slice(0, 25),
  };
  if (config.note) embed.description = config.note;
  if (config.showTimestamp) embed.timestamp = new Date().toISOString();
  return embed;
}

async function postToWebhook(config, url, embed) {
  const payload = { embeds: [embed] };
  if (config.username) payload.username = config.username;
  if (config.avatarUrl) payload.avatar_url = config.avatarUrl;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Discord webhook returned ${res.status}: ${text.slice(0, 300)}`);
  }
}

// Minimum wait between scheduled send attempts after a failure.
const RETRY_BACKOFF_MS = 5 * 60 * 1000;

// Core runner. `force` bypasses the enabled flag and interval gate (used by
// the panel's "Send test now" button).
async function runStockBot(env, { force }) {
  try {
    const config = await getStockConfig(env);

    if (!force && !config.enabled) {
      return { sent: false, skipped: true, reason: 'disabled' };
    }
    const targets = (config.webhooks || []).filter((w) => w.enabled !== false && w.url);
    if (!targets.length) {
      return { sent: false, skipped: true, reason: 'no-webhook', error: force ? 'No enabled webhooks with a URL configured.' : undefined };
    }
    if (!(config.groups || []).length) {
      return { sent: false, skipped: true, reason: 'no-groups', error: force ? 'No products configured to display.' : undefined };
    }

    if (!force) {
      const elapsed = Date.now() - (config.lastSentAt || 0);
      if (elapsed < config.intervalMinutes * 60 * 1000) {
        return { sent: false, skipped: true, reason: 'interval-not-elapsed' };
      }
      // Back off after a failed attempt instead of retrying every cron tick,
      // so a broken webhook doesn't hammer the NFA API once per minute.
      const sinceAttempt = Date.now() - (config.lastAttemptAt || 0);
      if (sinceAttempt < RETRY_BACKOFF_MS) {
        return { sent: false, skipped: true, reason: 'retry-backoff' };
      }
      config.lastAttemptAt = Date.now();
      await saveStockConfig(env, config);
    }

    const stock = await fetchNfaStock(env);
    const embed = buildStockEmbed(config, stock);

    // Deliver to every enabled webhook; collect per-target results.
    const results = await Promise.all(targets.map(async (w) => {
      try {
        await postToWebhook(config, w.url, embed);
        return { name: w.name || w.id, ok: true };
      } catch (err) {
        return { name: w.name || w.id, ok: false, error: err.message };
      }
    }));

    const delivered = results.filter((r) => r.ok).length;
    const failed = results.filter((r) => !r.ok);

    if (delivered > 0) {
      config.lastSentAt = Date.now();
      await saveStockConfig(env, config);
    }

    return {
      sent: delivered > 0,
      skipped: false,
      delivered,
      failed: failed.length,
      results,
      error: delivered === 0 && failed.length ? failed.map((f) => `${f.name}: ${f.error}`).join('; ') : undefined,
    };
  } catch (err) {
    return { sent: false, skipped: false, error: err.message };
  }
}
