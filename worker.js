/**
 * NFA Reseller API Proxy — Cloudflare Worker
 */

const NFA_ORIGIN = 'https://nfa-api.acode.ing';
const SELLER_API_ORIGIN = 'https://reselling.pro/api/scm';

// Leave empty to allow all origins.
const ALLOWED_ORIGINS = new Set(['*']);

// SellAuth Dynamic Delivery webhook path.
// Configure this URL in SellAuth: Product → Delivery → Dynamic.
const SELLAUTH_WEBHOOK_PATH = '/webhook/sellauth';

// Stock Discord bot — config API + KV key.
const STOCK_BOT_PREFIX = '/api/stock-bot/';
const STOCK_BOT_CONFIG_KEY = 'config';

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Panel-Auth',
    'Access-Control-Max-Age': '86400',
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const url = new URL(request.url);

    // --- SellAuth Dynamic Delivery webhook ---
    if (url.pathname === SELLAUTH_WEBHOOK_PATH) {
      return handleSellAuthWebhook(request, env);
    }

    // --- Stock Discord bot config/control API ---
    if (url.pathname.startsWith(STOCK_BOT_PREFIX)) {
      return handleStockBotApi(request, env, url);
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
    ctx.waitUntil(runStockBot(env, { force: false }));
  },
};

// ───────────────────────────────────────────────────────────────────────────
//  SellAuth Dynamic Delivery  →  reselling.pro Seller API
//  https://docs.sellauth.com/guides/dynamic-delivery
//
//  On checkout, SellAuth POSTs one request per invoice item. We verify the
//  HMAC-SHA256 signature, purchase key(s) via the reselling.pro Seller API,
//  and return them as plain text (one deliverable per line). HTTP 200 = delivered.
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

// Resolve the reselling.pro product+variant for a SellAuth item.
// Priority:
//   1. SELLAUTH_PRODUCT_MAP env (JSON) keyed by variant_id, then product_id.
//      Values are objects: { "productId": "UUID", "variantId": "UUID" }.
//   2. Custom fields named "product_id" / "variant_id" (or camelCase).
function resolveSellerProduct(item, env) {
  if (env.SELLAUTH_PRODUCT_MAP) {
    let map = null;
    try {
      map = JSON.parse(env.SELLAUTH_PRODUCT_MAP);
    } catch {
      map = null;
    }
    if (map) {
      const variantKey = item.variant_id != null ? String(item.variant_id) : null;
      const productKey = item.product_id != null ? String(item.product_id) : null;
      const entry = (variantKey && map[variantKey]) || (productKey && map[productKey]) || null;
      if (entry && typeof entry === 'object' && entry.productId) {
        return { productId: entry.productId, variantId: entry.variantId || undefined };
      }
      if (typeof entry === 'string' && entry) {
        return { productId: entry };
      }
    }
  }

  const fields = item.custom_fields || {};
  let productId = null;
  let variantId = null;
  for (const [name, value] of Object.entries(fields)) {
    const n = name.trim().toLowerCase();
    if ((n === 'product_id' || n === 'productid') && value) productId = String(value);
    if ((n === 'variant_id' || n === 'variantid') && value) variantId = String(value);
  }
  if (productId) return { productId, variantId: variantId || undefined };

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

  if (!env.SELLER_API_KEY) {
    return plain(500, 'Server configuration error: SELLER_API_KEY is not set');
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return plain(400, 'Invalid JSON body');
  }

  const item = payload.item || {};
  const sellerProduct = resolveSellerProduct(item, env);
  if (!sellerProduct) {
    return plain(400, 'Unable to determine product for this item. Configure SELLAUTH_PRODUCT_MAP with { productId, variantId } entries or set custom fields.');
  }

  const quantity = Number(item.quantity) > 0 ? Number(item.quantity) : 1;

  const reqBody = {
    productId: sellerProduct.productId,
    source: 'public',
    quantity,
  };
  if (sellerProduct.variantId) reqBody.variantId = sellerProduct.variantId;
  if (payload.invoice_id) reqBody.order_id = String(payload.invoice_id);

  let apiResponse;
  try {
    apiResponse = await fetch(`${SELLER_API_ORIGIN}/sellerapi/keys`, {
      method: 'POST',
      headers: {
        'X-API-Key': env.SELLER_API_KEY,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(reqBody),
    });
  } catch (err) {
    return plain(502, 'Upstream request failed: ' + err.message);
  }

  let data = null;
  const text = await apiResponse.text();
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (!apiResponse.ok || (data && data.success === false)) {
    const message = (data && data.message) || text || 'Failed to purchase keys';
    const status = apiResponse.status >= 500 ? 502 : 400;
    return plain(status, message);
  }

  const keys = extractKeys(data);
  if (!keys.length) {
    return plain(400, (data && data.message) || 'No keys were returned for this order.');
  }

  return plain(200, keys.join('\n'));
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
  groups: [],
  lastSentAt: 0,
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

// Fetch the live stock map from the NFA API using the server-side key.
async function fetchNfaStock(env) {
  if (!env.NFA_API_KEY) throw new Error('NFA_API_KEY is not set');
  const res = await fetch(`${NFA_ORIGIN}/api/v1/stock`, {
    method: 'GET',
    headers: {
      'X-API-Key': env.NFA_API_KEY,
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
  return (data && data.stock) || {};
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
