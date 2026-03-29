import { Hono } from 'hono';
import { cors } from 'hono/cors';

// ═══════════════════════════════════════════════════════════════════
// ECHO CRM v2.0.0 — AI-Powered Customer Relationship Management
// D1 + KV + Engine Runtime + Shared Brain + Stripe Payments
// ═══════════════════════════════════════════════════════════════════

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ENGINE_RUNTIME: Fetcher;
  SHARED_BRAIN: Fetcher;
  ECHO_API_KEY?: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
}

// ── Helpers ──────────────────────────────────────────────────────

function uid(): string { return crypto.randomUUID().replace(/-/g, '').slice(0, 16); }
function nowISO(): string { return new Date().toISOString().replace('T', ' ').replace('Z', ''); }

function log(level: string, msg: string, extra: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, service: 'echo-crm', ...extra }));
}

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Echo-API-Key',
};

function ok(data: Record<string, unknown> = {}): Response {
  return Response.json({ ok: true, ...data }, { headers: CORS_HEADERS });
}

function fail(error: string, status = 400): Response {
  return Response.json({ ok: false, error }, { status, headers: CORS_HEADERS });
}

function requireBody(body: unknown, ...fields: string[]): string | null {
  if (!body || typeof body !== 'object') return 'Missing request body';
  for (const f of fields) {
    if ((body as Record<string, unknown>)[f] === undefined || (body as Record<string, unknown>)[f] === null) {
      return `Missing required field: ${f}`;
    }
  }
  return null;
}

function paginate(url: URL): { limit: number; offset: number } {
  const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 200);
  const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);
  return { limit, offset };
}

function sanitize(input: string, maxLen = 2000): string {
  if (typeof input !== 'string') return '';
  return input.slice(0, maxLen).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
}

// ── Stripe Plans ──────────────────────────────────────────────────

const CRM_PLANS = [
  { id: 'free', name: 'Free', price: 0, interval: 'month', features: ['50 contacts', '1 pipeline', 'Basic analytics', 'Email support'], limits: { contacts: 50, pipelines: 1, deals: 20 } },
  { id: 'starter', name: 'Starter', price: 29.99, interval: 'month', features: ['500 contacts', '3 pipelines', 'Lead scoring', 'Import/export', 'Priority support'], limits: { contacts: 500, pipelines: 3, deals: 200 } },
  { id: 'professional', name: 'Professional', price: 79.99, interval: 'month', features: ['5,000 contacts', '10 pipelines', 'AI lead scoring', 'Custom fields', 'API access', 'Integrations'], limits: { contacts: 5000, pipelines: 10, deals: 2000 } },
  { id: 'enterprise', name: 'Enterprise', price: 199.99, interval: 'month', features: ['Unlimited contacts', 'Unlimited pipelines', 'Dedicated support', 'Custom integrations', 'White-label', 'SLA'], limits: { contacts: -1, pipelines: -1, deals: -1 } },
] as const;

// ── Stripe Signature Verification ────────────────────────────────

async function verifyStripeSignature(payload: string, sigHeader: string, secret: string): Promise<boolean> {
  try {
    const parts = sigHeader.split(',');
    let timestamp = '';
    let signature = '';
    for (const part of parts) {
      const [key, val] = part.trim().split('=');
      if (key === 't') timestamp = val;
      if (key === 'v1') signature = val;
    }
    if (!timestamp || !signature) return false;

    // Replay protection: reject if older than 5 minutes
    const ts = parseInt(timestamp, 10);
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - ts) > 300) return false;

    // HMAC-SHA256 with Web Crypto API
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signedPayload = `${timestamp}.${payload}`;
    const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
    const computed = Array.from(new Uint8Array(mac)).map(b => b.toString(16).padStart(2, '0')).join('');

    // Constant-time comparison via XOR
    if (computed.length !== signature.length) return false;
    let diff = 0;
    for (let i = 0; i < computed.length; i++) {
      diff |= computed.charCodeAt(i) ^ signature.charCodeAt(i);
    }
    return diff === 0;
  } catch {
    return false;
  }
}

// Rate Limiting
interface RLState { c: number; t: number }
async function checkRateLimit(kv: KVNamespace, key: string, limit: number, windowSec: number): Promise<{ allowed: boolean; remaining: number; reset: number }> {
  const rlKey = `rl:${key}`;
  const now = Math.floor(Date.now() / 1000);
  const raw = await kv.get(rlKey, 'json') as RLState | null;
  let count: number, windowStart: number;
  if (!raw || (now - raw.t) >= windowSec) { count = 1; windowStart = now; }
  else { const elapsed = now - raw.t; const decay = Math.max(0, 1 - elapsed / windowSec); count = Math.floor(raw.c * decay) + 1; windowStart = raw.t; }
  const allowed = count <= limit;
  await kv.put(rlKey, JSON.stringify({ c: count, t: windowStart } as RLState), { expirationTtl: windowSec * 2 });
  return { allowed, remaining: Math.max(0, limit - count), reset: windowSec - (now - windowStart) };
}

async function logActivity(db: D1Database, entityType: string, entityId: string, action: string, details?: string, createdBy?: string): Promise<void> {
  try {
    await db.prepare("INSERT INTO activity_log (entity_type, entity_id, action, details, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(entityType, entityId, action, details || null, createdBy || null, nowISO()).run();
  } catch { /* best effort */ }
}

// ── App ──────────────────────────────────────────────────────────

const app = new Hono<{ Bindings: Env }>();

// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});

app.use('*', cors({
  origin: ['https://echo-ept.com', 'https://www.echo-ept.com', 'https://echo-op.com', 'http://localhost:3000'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Echo-API-Key'],
  maxAge: 86400,
}));

// Rate limiting — 60 writes/min, 200 reads/min per IP
app.use('*', async (c, next) => {
  const path = new URL(c.req.url).pathname;
  if (path === '/health' || path === '/' || path === '/status' || path === '/plans' || path === '/webhooks/stripe') return next();
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown';
  const isWrite = ['POST', 'PUT', 'DELETE'].includes(c.req.method);
  const limit = isWrite ? 60 : 200;
  const rlKey = `crm:${ip}:${isWrite ? 'w' : 'r'}`;
  const { allowed, remaining, reset } = await checkRateLimit(c.env.CACHE, rlKey, limit, 60);
  c.header('X-RateLimit-Limit', String(limit));
  c.header('X-RateLimit-Remaining', String(remaining));
  c.header('X-RateLimit-Reset', String(reset));
  if (!allowed) {
    log('warn', 'Rate limited', { ip, path, method: c.req.method });
    return c.json({ ok: false, error: 'Rate limit exceeded. Try again shortly.' }, 429);
  }
  return next();
});

// ── Auth Middleware — writes require API key ─────────────────────
app.use('*', async (c, next) => {
  const method = c.req.method;
  const path = new URL(c.req.url).pathname;
  if (method === 'GET' || method === 'OPTIONS' || method === 'HEAD' || path === '/health' || path === '/status' || path === '/webhooks/stripe') return next();
  const apiKey = c.req.header('X-Echo-API-Key') || '';
  const bearer = (c.req.header('Authorization') || '').replace('Bearer ', '');
  const expected = c.env.ECHO_API_KEY;
  if (!expected || (apiKey !== expected && bearer !== expected)) {
    return c.json({ ok: false, error: 'Unauthorized — X-Echo-API-Key or Bearer token required' }, 401);
  }
  return next();
});

// ═══════════════════════════════════════════════════════════════════
// HEALTH & STATUS
// ═══════════════════════════════════════════════════════════════════

app.get('/', (c) => c.json({ service: 'echo-crm', version: '2.0.0', status: 'operational' }));

app.get('/health', async (c) => {
  let dbOk = false;
  try { const r = await c.env.DB.prepare("SELECT 1 AS ping").first(); dbOk = r?.ping === 1; } catch { /* */ }
  return ok({ service: 'echo-crm', version: '2.0.0', d1: dbOk ? 'connected' : 'offline', stripe: !!c.env.STRIPE_SECRET_KEY, ts: new Date().toISOString() });
});

app.get('/status', async (c) => {
  try {
    const [contacts, companies, deals, activities, pipelines] = await Promise.all([
      c.env.DB.prepare("SELECT COUNT(*) AS n FROM contacts").first<{ n: number }>(),
      c.env.DB.prepare("SELECT COUNT(*) AS n FROM companies").first<{ n: number }>(),
      c.env.DB.prepare("SELECT COUNT(*) AS n FROM deals").first<{ n: number }>(),
      c.env.DB.prepare("SELECT COUNT(*) AS n FROM activities").first<{ n: number }>(),
      c.env.DB.prepare("SELECT COUNT(*) AS n FROM pipelines").first<{ n: number }>(),
    ]);
    return ok({
      service: 'echo-crm', version: '2.0.0',
      contacts: contacts?.n || 0, companies: companies?.n || 0, deals: deals?.n || 0,
      activities: activities?.n || 0, pipelines: pipelines?.n || 0,
      endpoints: 72, tables: 12, modules: 10,
    });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: '/status', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// PIPELINES & STAGES
// ═══════════════════════════════════════════════════════════════════

app.get('/pipelines', async (c) => {
  try {
    const rows = await c.env.DB.prepare("SELECT * FROM pipelines ORDER BY created_at DESC").all();
    return ok({ pipelines: rows.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: '/pipelines', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/pipelines', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'name');
  if (err) return fail(err);
  const id = uid();
  try {
    await c.env.DB.prepare("INSERT INTO pipelines (id, name, is_default) VALUES (?, ?, ?)").bind(id, sanitize(body!.name as string, 100), body!.is_default ? 1 : 0).run();
    log('info', 'Pipeline created', { id });
    return ok({ id });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /pipelines', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/pipelines/:id', async (c) => {
  try {
    const row = await c.env.DB.prepare("SELECT * FROM pipelines WHERE id = ?").bind(c.req.param('id')).first();
    if (!row) return fail('Pipeline not found', 404);
    const stages = await c.env.DB.prepare("SELECT * FROM deal_stages WHERE pipeline_id = ? ORDER BY position").bind(c.req.param('id')).all();
    return ok({ pipeline: row, stages: stages.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /pipelines/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.delete('/pipelines/:id', async (c) => {
  try {
    await c.env.DB.prepare("DELETE FROM pipelines WHERE id = ?").bind(c.req.param('id')).run();
    return ok({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'DELETE /pipelines/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Deal stages
app.get('/pipelines/:id/stages', async (c) => {
  try {
    const rows = await c.env.DB.prepare("SELECT * FROM deal_stages WHERE pipeline_id = ? ORDER BY position").bind(c.req.param('id')).all();
    return ok({ stages: rows.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /pipelines/:id/stages', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/pipelines/:id/stages', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'name');
  if (err) return fail(err);
  const id = uid();
  try {
    await c.env.DB.prepare("INSERT INTO deal_stages (id, pipeline_id, name, position, probability, rotting_days) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(id, c.req.param('id'), sanitize(body!.name as string, 100), body!.position || 0, body!.probability || 0, body!.rotting_days || 30).run();
    return ok({ id });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /pipelines/:id/stages', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.put('/stages/:id', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  if (!body) return fail('Missing body');
  const sets: string[] = [];
  const vals: unknown[] = [];
  for (const [k, v] of Object.entries(body)) {
    if (['name', 'position', 'probability', 'rotting_days'].includes(k)) {
      sets.push(`${k} = ?`);
      vals.push(typeof v === 'string' ? sanitize(v, 100) : v);
    }
  }
  if (sets.length === 0) return fail('No valid fields');
  vals.push(c.req.param('id'));
  try {
    await c.env.DB.prepare(`UPDATE deal_stages SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
    return ok({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'PUT /stages/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.delete('/stages/:id', async (c) => {
  try {
    const activeDeals = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM deals WHERE stage_id = ?").bind(c.req.param('id')).first<{ n: number }>();
    if (activeDeals && activeDeals.n > 0) return fail('Cannot delete stage with active deals');
    await c.env.DB.prepare("DELETE FROM deal_stages WHERE id = ?").bind(c.req.param('id')).run();
    return ok({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'DELETE /stages/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// CONTACTS
// ═══════════════════════════════════════════════════════════════════

app.get('/contacts', async (c) => {
  const url = new URL(c.req.url);
  const { limit, offset } = paginate(url);
  const search = url.searchParams.get('q');
  const status = url.searchParams.get('status');
  const source = url.searchParams.get('source');

  let where = '1=1';
  const binds: unknown[] = [];

  if (search) { where += ' AND (first_name LIKE ? OR last_name LIKE ? OR email LIKE ?)'; const s = `%${search}%`; binds.push(s, s, s); }
  if (status) { where += ' AND lead_status = ?'; binds.push(status); }
  if (source) { where += ' AND source = ?'; binds.push(source); }

  binds.push(limit, offset);
  try {
    const rows = await c.env.DB.prepare(`SELECT c.*, co.name AS company_name FROM contacts c LEFT JOIN companies co ON c.company_id = co.id WHERE ${where} ORDER BY c.created_at DESC LIMIT ? OFFSET ?`).bind(...binds).all();
    const total = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM contacts WHERE ${where}`).bind(...binds.slice(0, -2)).first<{ n: number }>();
    return ok({ contacts: rows.results, total: total?.n || 0 });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /contacts', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/contacts', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'first_name');
  if (err) return fail(err);
  const id = uid();
  const now = nowISO();
  try {
    await c.env.DB.prepare(
      "INSERT INTO contacts (id, company_id, first_name, last_name, email, phone, title, source, lead_status, tags, custom_fields, address, city, state, zip, country, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      id, body!.company_id || null, sanitize(body!.first_name as string, 100), sanitize((body!.last_name || '') as string, 100),
      sanitize((body!.email || '') as string, 200), sanitize((body!.phone || '') as string, 30), sanitize((body!.title || '') as string, 100),
      body!.source || 'manual', body!.lead_status || 'new',
      JSON.stringify(body!.tags || []), JSON.stringify(body!.custom_fields || {}),
      sanitize((body!.address || '') as string, 200), sanitize((body!.city || '') as string, 100),
      sanitize((body!.state || '') as string, 50), sanitize((body!.zip || '') as string, 20),
      body!.country || 'US', sanitize((body!.notes || '') as string, 5000), now, now
    ).run();
    await logActivity(c.env.DB, 'contact', id, 'created', `${body!.first_name} ${body!.last_name || ''}`);
    log('info', 'Contact created', { id });
    return ok({ id });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /contacts', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/contacts/:id', async (c) => {
  try {
    const row = await c.env.DB.prepare("SELECT c.*, co.name AS company_name FROM contacts c LEFT JOIN companies co ON c.company_id = co.id WHERE c.id = ?").bind(c.req.param('id')).first();
    if (!row) return fail('Contact not found', 404);
    const deals = await c.env.DB.prepare("SELECT id, title, value, status, stage_id FROM deals WHERE contact_id = ? ORDER BY created_at DESC LIMIT 10").bind(c.req.param('id')).all();
    const recentActivities = await c.env.DB.prepare("SELECT * FROM activities WHERE contact_id = ? ORDER BY created_at DESC LIMIT 10").bind(c.req.param('id')).all();
    return ok({ contact: row, deals: deals.results, activities: recentActivities.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /contacts/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.put('/contacts/:id', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  if (!body) return fail('Missing body');
  const allowed = ['first_name', 'last_name', 'email', 'phone', 'title', 'company_id', 'source', 'lead_status', 'lead_score', 'tags', 'custom_fields', 'address', 'city', 'state', 'zip', 'country', 'notes'];
  const sets: string[] = ['updated_at = ?'];
  const vals: unknown[] = [nowISO()];
  for (const [k, v] of Object.entries(body)) {
    if (allowed.includes(k)) {
      sets.push(`${k} = ?`);
      if (k === 'tags' || k === 'custom_fields') vals.push(JSON.stringify(v));
      else if (typeof v === 'string') vals.push(sanitize(v, k === 'notes' ? 5000 : 200));
      else vals.push(v);
    }
  }
  vals.push(c.req.param('id'));
  try {
    await c.env.DB.prepare(`UPDATE contacts SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
    return ok({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'PUT /contacts/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.delete('/contacts/:id', async (c) => {
  try {
    await c.env.DB.batch([
      c.env.DB.prepare("DELETE FROM deals WHERE contact_id = ?").bind(c.req.param('id')),
      c.env.DB.prepare("DELETE FROM activities WHERE contact_id = ?").bind(c.req.param('id')),
      c.env.DB.prepare("DELETE FROM notes WHERE contact_id = ?").bind(c.req.param('id')),
      c.env.DB.prepare("DELETE FROM email_events WHERE contact_id = ?").bind(c.req.param('id')),
      c.env.DB.prepare("DELETE FROM contacts WHERE id = ?").bind(c.req.param('id')),
    ]);
    return ok({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'DELETE /contacts/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// COMPANIES
// ═══════════════════════════════════════════════════════════════════

app.get('/companies', async (c) => {
  const url = new URL(c.req.url);
  const { limit, offset } = paginate(url);
  const search = url.searchParams.get('q');
  const industry = url.searchParams.get('industry');

  let where = '1=1';
  const binds: unknown[] = [];
  if (search) { where += ' AND (name LIKE ? OR domain LIKE ?)'; const s = `%${search}%`; binds.push(s, s); }
  if (industry) { where += ' AND industry = ?'; binds.push(industry); }

  binds.push(limit, offset);
  try {
    const rows = await c.env.DB.prepare(`SELECT * FROM companies WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(...binds).all();
    const total = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM companies WHERE ${where}`).bind(...binds.slice(0, -2)).first<{ n: number }>();
    return ok({ companies: rows.results, total: total?.n || 0 });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /companies', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/companies', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'name');
  if (err) return fail(err);
  const id = uid();
  const now = nowISO();
  try {
    await c.env.DB.prepare(
      "INSERT INTO companies (id, name, domain, industry, size, revenue, phone, address, city, state, zip, country, tags, custom_fields, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      id, sanitize(body!.name as string, 200), sanitize((body!.domain || '') as string, 200),
      sanitize((body!.industry || '') as string, 100), body!.size || null, body!.revenue || null,
      sanitize((body!.phone || '') as string, 30), sanitize((body!.address || '') as string, 200),
      sanitize((body!.city || '') as string, 100), sanitize((body!.state || '') as string, 50),
      sanitize((body!.zip || '') as string, 20), body!.country || 'US',
      JSON.stringify(body!.tags || []), JSON.stringify(body!.custom_fields || {}),
      sanitize((body!.notes || '') as string, 5000), now, now
    ).run();
    await logActivity(c.env.DB, 'company', id, 'created', body!.name as string);
    log('info', 'Company created', { id });
    return ok({ id });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /companies', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/companies/:id', async (c) => {
  try {
    const row = await c.env.DB.prepare("SELECT * FROM companies WHERE id = ?").bind(c.req.param('id')).first();
    if (!row) return fail('Company not found', 404);
    const contactCount = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM contacts WHERE company_id = ?").bind(c.req.param('id')).first<{ n: number }>();
    const dealSum = await c.env.DB.prepare("SELECT SUM(value) AS total, COUNT(*) AS n FROM deals WHERE company_id = ? AND status = 'won'").bind(c.req.param('id')).first<{ total: number; n: number }>();
    return ok({ company: row, contacts: contactCount?.n || 0, won_deals: dealSum?.n || 0, total_revenue: dealSum?.total || 0 });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /companies/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.put('/companies/:id', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  if (!body) return fail('Missing body');
  const allowed = ['name', 'domain', 'industry', 'size', 'revenue', 'phone', 'address', 'city', 'state', 'zip', 'country', 'tags', 'custom_fields', 'notes'];
  const sets: string[] = ['updated_at = ?'];
  const vals: unknown[] = [nowISO()];
  for (const [k, v] of Object.entries(body)) {
    if (allowed.includes(k)) {
      sets.push(`${k} = ?`);
      if (k === 'tags' || k === 'custom_fields') vals.push(JSON.stringify(v));
      else if (typeof v === 'string') vals.push(sanitize(v, k === 'notes' ? 5000 : 200));
      else vals.push(v);
    }
  }
  vals.push(c.req.param('id'));
  try {
    await c.env.DB.prepare(`UPDATE companies SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
    return ok({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'PUT /companies/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.delete('/companies/:id', async (c) => {
  try {
    await c.env.DB.batch([
      c.env.DB.prepare("UPDATE contacts SET company_id = NULL WHERE company_id = ?").bind(c.req.param('id')),
      c.env.DB.prepare("DELETE FROM notes WHERE company_id = ?").bind(c.req.param('id')),
      c.env.DB.prepare("DELETE FROM activities WHERE company_id = ?").bind(c.req.param('id')),
      c.env.DB.prepare("DELETE FROM companies WHERE id = ?").bind(c.req.param('id')),
    ]);
    return ok({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'DELETE /companies/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// DEALS
// ═══════════════════════════════════════════════════════════════════

app.get('/deals', async (c) => {
  const url = new URL(c.req.url);
  const { limit, offset } = paginate(url);
  const pipelineId = url.searchParams.get('pipeline_id');
  const stageId = url.searchParams.get('stage_id');
  const status = url.searchParams.get('status');

  let where = '1=1';
  const binds: unknown[] = [];
  if (pipelineId) { where += ' AND d.pipeline_id = ?'; binds.push(pipelineId); }
  if (stageId) { where += ' AND d.stage_id = ?'; binds.push(stageId); }
  if (status) { where += ' AND d.status = ?'; binds.push(status); }

  binds.push(limit, offset);
  try {
    const rows = await c.env.DB.prepare(`SELECT d.*, c.first_name || ' ' || COALESCE(c.last_name, '') AS contact_name, co.name AS company_name, ds.name AS stage_name FROM deals d LEFT JOIN contacts c ON d.contact_id = c.id LEFT JOIN companies co ON d.company_id = co.id LEFT JOIN deal_stages ds ON d.stage_id = ds.id WHERE ${where} ORDER BY d.created_at DESC LIMIT ? OFFSET ?`).bind(...binds).all();
    const total = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM deals d WHERE ${where}`).bind(...binds.slice(0, -2)).first<{ n: number }>();
    return ok({ deals: rows.results, total: total?.n || 0 });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /deals', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Deal board view — grouped by stage
app.get('/deals/board', async (c) => {
  const pipelineId = new URL(c.req.url).searchParams.get('pipeline_id');
  if (!pipelineId) return fail('pipeline_id required');
  try {
    const stages = await c.env.DB.prepare("SELECT * FROM deal_stages WHERE pipeline_id = ? ORDER BY position").bind(pipelineId).all();
    const deals = await c.env.DB.prepare("SELECT d.*, c.first_name || ' ' || COALESCE(c.last_name, '') AS contact_name FROM deals d LEFT JOIN contacts c ON d.contact_id = c.id WHERE d.pipeline_id = ? AND d.status = 'open' ORDER BY d.created_at DESC").bind(pipelineId).all();
    const board = (stages.results as Record<string, unknown>[]).map(stage => ({
      ...stage,
      deals: (deals.results as Record<string, unknown>[]).filter(d => d.stage_id === stage.id),
    }));
    return ok({ board });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /deals/board', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/deals', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'title', 'pipeline_id', 'stage_id');
  if (err) return fail(err);
  const id = uid();
  const now = nowISO();
  try {
    await c.env.DB.prepare(
      "INSERT INTO deals (id, pipeline_id, stage_id, contact_id, company_id, title, value, currency, probability, expected_close_date, status, owner, tags, custom_fields, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      id, body!.pipeline_id, body!.stage_id, body!.contact_id || null, body!.company_id || null,
      sanitize(body!.title as string, 200), body!.value || 0, body!.currency || 'USD',
      body!.probability || 0, body!.expected_close_date || null, 'open',
      sanitize((body!.owner || '') as string, 100), JSON.stringify(body!.tags || []),
      JSON.stringify(body!.custom_fields || {}), sanitize((body!.notes || '') as string, 5000), now, now
    ).run();
    await logActivity(c.env.DB, 'deal', id, 'created', `${body!.title} ($${body!.value || 0})`);
    log('info', 'Deal created', { id, value: body!.value });
    return ok({ id });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /deals', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/deals/:id', async (c) => {
  try {
    const row = await c.env.DB.prepare("SELECT d.*, c.first_name || ' ' || COALESCE(c.last_name, '') AS contact_name, co.name AS company_name, ds.name AS stage_name FROM deals d LEFT JOIN contacts c ON d.contact_id = c.id LEFT JOIN companies co ON d.company_id = co.id LEFT JOIN deal_stages ds ON d.stage_id = ds.id WHERE d.id = ?").bind(c.req.param('id')).first();
    if (!row) return fail('Deal not found', 404);
    const activities = await c.env.DB.prepare("SELECT * FROM activities WHERE deal_id = ? ORDER BY created_at DESC LIMIT 20").bind(c.req.param('id')).all();
    const notes = await c.env.DB.prepare("SELECT * FROM notes WHERE deal_id = ? ORDER BY created_at DESC").bind(c.req.param('id')).all();
    return ok({ deal: row, activities: activities.results, notes: notes.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /deals/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.put('/deals/:id', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  if (!body) return fail('Missing body');
  const allowed = ['stage_id', 'title', 'value', 'currency', 'probability', 'expected_close_date', 'status', 'lost_reason', 'won_reason', 'owner', 'contact_id', 'company_id', 'tags', 'custom_fields', 'notes'];
  const sets: string[] = ['updated_at = ?'];
  const vals: unknown[] = [nowISO()];
  for (const [k, v] of Object.entries(body)) {
    if (allowed.includes(k)) {
      sets.push(`${k} = ?`);
      if (k === 'tags' || k === 'custom_fields') vals.push(JSON.stringify(v));
      else if (typeof v === 'string') vals.push(sanitize(v, k === 'notes' ? 5000 : 200));
      else vals.push(v);
    }
  }
  // Auto-set close dates
  if (body.status === 'won' || body.status === 'lost') {
    sets.push('actual_close_date = ?');
    vals.push(nowISO());
  }
  vals.push(c.req.param('id'));
  try {
    await c.env.DB.prepare(`UPDATE deals SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
    if (body.status) await logActivity(c.env.DB, 'deal', c.req.param('id'), `status_${body.status}`, body.lost_reason as string || body.won_reason as string || undefined);
    if (body.stage_id) await logActivity(c.env.DB, 'deal', c.req.param('id'), 'stage_moved');
    return ok({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'PUT /deals/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.delete('/deals/:id', async (c) => {
  try {
    await c.env.DB.batch([
      c.env.DB.prepare("DELETE FROM activities WHERE deal_id = ?").bind(c.req.param('id')),
      c.env.DB.prepare("DELETE FROM notes WHERE deal_id = ?").bind(c.req.param('id')),
      c.env.DB.prepare("DELETE FROM deals WHERE id = ?").bind(c.req.param('id')),
    ]);
    return ok({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'DELETE /deals/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Move deal to stage
app.post('/deals/:id/move', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'stage_id');
  if (err) return fail(err);
  try {
    // Get stage probability
    const stage = await c.env.DB.prepare("SELECT probability FROM deal_stages WHERE id = ?").bind(body!.stage_id).first<{ probability: number }>();
    if (!stage) return c.json({ error: 'Stage not found' }, 404);
    await c.env.DB.prepare("UPDATE deals SET stage_id = ?, probability = ?, updated_at = ? WHERE id = ?")
      .bind(body!.stage_id, stage?.probability || 0, nowISO(), c.req.param('id')).run();
    await logActivity(c.env.DB, 'deal', c.req.param('id'), 'stage_moved');
    return ok({ moved: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /deals/:id/move', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// ACTIVITIES
// ═══════════════════════════════════════════════════════════════════

app.get('/activities', async (c) => {
  const url = new URL(c.req.url);
  const { limit, offset } = paginate(url);
  const type = url.searchParams.get('type');
  const contactId = url.searchParams.get('contact_id');
  const dealId = url.searchParams.get('deal_id');
  const upcoming = url.searchParams.get('upcoming');

  let where = '1=1';
  const binds: unknown[] = [];
  if (type) { where += ' AND type = ?'; binds.push(type); }
  if (contactId) { where += ' AND contact_id = ?'; binds.push(contactId); }
  if (dealId) { where += ' AND deal_id = ?'; binds.push(dealId); }
  if (upcoming === 'true') { where += " AND due_date >= date('now') AND is_done = 0"; }

  const order = upcoming === 'true' ? 'due_date ASC' : 'created_at DESC';
  binds.push(limit, offset);
  try {
    const rows = await c.env.DB.prepare(`SELECT a.*, c.first_name || ' ' || COALESCE(c.last_name, '') AS contact_name FROM activities a LEFT JOIN contacts c ON a.contact_id = c.id WHERE ${where} ORDER BY ${order} LIMIT ? OFFSET ?`).bind(...binds).all();
    return ok({ activities: rows.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /activities', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/activities', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'type', 'subject');
  if (err) return fail(err);
  const id = uid();
  try {
    await c.env.DB.prepare(
      "INSERT INTO activities (id, contact_id, company_id, deal_id, type, subject, body, due_date, duration_minutes, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      id, body!.contact_id || null, body!.company_id || null, body!.deal_id || null,
      sanitize(body!.type as string, 50), sanitize(body!.subject as string, 200),
      sanitize((body!.body || '') as string, 5000), body!.due_date || null,
      body!.duration_minutes || null, body!.created_by || null, nowISO()
    ).run();
    // Update last_contacted_at on contact
    if (body!.contact_id) {
      await c.env.DB.prepare("UPDATE contacts SET last_contacted_at = ? WHERE id = ?").bind(nowISO(), body!.contact_id).run();
    }
    log('info', 'Activity created', { id, type: body!.type });
    return ok({ id });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /activities', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.put('/activities/:id', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  if (!body) return fail('Missing body');
  try {
    if (body.is_done === true || body.is_done === 1) {
      await c.env.DB.prepare("UPDATE activities SET is_done = 1, completed_at = ? WHERE id = ?").bind(nowISO(), c.req.param('id')).run();
    } else {
      const allowed = ['subject', 'body', 'due_date', 'duration_minutes', 'type'];
      const sets: string[] = [];
      const vals: unknown[] = [];
      for (const [k, v] of Object.entries(body)) {
        if (allowed.includes(k)) { sets.push(`${k} = ?`); vals.push(typeof v === 'string' ? sanitize(v, 5000) : v); }
      }
      if (sets.length > 0) { vals.push(c.req.param('id')); await c.env.DB.prepare(`UPDATE activities SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run(); }
    }
    return ok({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'PUT /activities/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.delete('/activities/:id', async (c) => {
  try {
    await c.env.DB.prepare("DELETE FROM activities WHERE id = ?").bind(c.req.param('id')).run();
    return ok({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'DELETE /activities/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// NOTES
// ═══════════════════════════════════════════════════════════════════

app.get('/notes', async (c) => {
  const url = new URL(c.req.url);
  const contactId = url.searchParams.get('contact_id');
  const dealId = url.searchParams.get('deal_id');
  const companyId = url.searchParams.get('company_id');

  let where = '1=1';
  const binds: unknown[] = [];
  if (contactId) { where += ' AND contact_id = ?'; binds.push(contactId); }
  if (dealId) { where += ' AND deal_id = ?'; binds.push(dealId); }
  if (companyId) { where += ' AND company_id = ?'; binds.push(companyId); }

  try {
    const rows = await c.env.DB.prepare(`SELECT * FROM notes WHERE ${where} ORDER BY created_at DESC LIMIT 100`).bind(...binds).all();
    return ok({ notes: rows.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /notes', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/notes', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'body');
  if (err) return fail(err);
  const id = uid();
  try {
    await c.env.DB.prepare("INSERT INTO notes (id, contact_id, company_id, deal_id, body, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(id, body!.contact_id || null, body!.company_id || null, body!.deal_id || null, sanitize(body!.body as string, 10000), body!.created_by || null, nowISO()).run();
    return ok({ id });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /notes', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.delete('/notes/:id', async (c) => {
  try {
    await c.env.DB.prepare("DELETE FROM notes WHERE id = ?").bind(c.req.param('id')).run();
    return ok({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'DELETE /notes/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// TAGS
// ═══════════════════════════════════════════════════════════════════

app.get('/tags', async (c) => {
  try {
    const rows = await c.env.DB.prepare("SELECT * FROM tags ORDER BY name").all();
    return ok({ tags: rows.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /tags', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/tags', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'name');
  if (err) return fail(err);
  const id = uid();
  try {
    await c.env.DB.prepare("INSERT INTO tags (id, name, color) VALUES (?, ?, ?)").bind(id, sanitize(body!.name as string, 50), body!.color || '#6366f1').run();
    return ok({ id });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /tags', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.delete('/tags/:id', async (c) => {
  try {
    await c.env.DB.prepare("DELETE FROM tags WHERE id = ?").bind(c.req.param('id')).run();
    return ok({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'DELETE /tags/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// EMAIL EVENTS (webhook receiver)
// ═══════════════════════════════════════════════════════════════════

app.post('/email-events', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'type', 'contact_id');
  if (err) return fail(err);
  const id = uid();
  try {
    await c.env.DB.prepare("INSERT INTO email_events (id, contact_id, deal_id, type, subject, opened_at, clicked_at, bounced, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(id, body!.contact_id, body!.deal_id || null, body!.type, sanitize((body!.subject || '') as string, 200),
        body!.type === 'opened' ? nowISO() : null, body!.type === 'clicked' ? nowISO() : null,
        body!.type === 'bounced' ? 1 : 0, nowISO()).run();
    return ok({ id });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /email-events', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/email-events', async (c) => {
  const contactId = new URL(c.req.url).searchParams.get('contact_id');
  if (!contactId) return fail('contact_id required');
  try {
    const rows = await c.env.DB.prepare("SELECT * FROM email_events WHERE contact_id = ? ORDER BY created_at DESC LIMIT 50").bind(contactId).all();
    return ok({ events: rows.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /email-events', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// LEAD SCORING
// ═══════════════════════════════════════════════════════════════════

app.get('/lead-scoring/rules', async (c) => {
  try {
    const rows = await c.env.DB.prepare("SELECT * FROM lead_scoring_rules WHERE is_active = 1 ORDER BY created_at").all();
    return ok({ rules: rows.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /lead-scoring/rules', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/lead-scoring/rules', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'field', 'operator', 'value', 'score');
  if (err) return fail(err);
  const id = uid();
  try {
    await c.env.DB.prepare("INSERT INTO lead_scoring_rules (id, field, operator, value, score) VALUES (?, ?, ?, ?, ?)")
      .bind(id, sanitize(body!.field as string, 50), sanitize(body!.operator as string, 20), sanitize(body!.value as string, 200), body!.score).run();
    return ok({ id });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /lead-scoring/rules', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.delete('/lead-scoring/rules/:id', async (c) => {
  try {
    await c.env.DB.prepare("DELETE FROM lead_scoring_rules WHERE id = ?").bind(c.req.param('id')).run();
    return ok({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'DELETE /lead-scoring/rules/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// AI lead scoring
app.post('/lead-scoring/score', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'contact_id');
  if (err) return fail(err);

  try {
    const contact = await c.env.DB.prepare("SELECT * FROM contacts WHERE id = ?").bind(body!.contact_id).first();
    if (!contact) return fail('Contact not found', 404);

    // Rule-based scoring
    const rules = await c.env.DB.prepare("SELECT * FROM lead_scoring_rules WHERE is_active = 1").all();
    let score = 0;
    for (const rule of rules.results as Record<string, unknown>[]) {
      const fieldVal = (contact as Record<string, unknown>)[rule.field as string];
      if (fieldVal !== undefined) {
        const op = rule.operator as string;
        const ruleVal = rule.value as string;
        if (op === 'equals' && String(fieldVal) === ruleVal) score += rule.score as number;
        else if (op === 'contains' && String(fieldVal).includes(ruleVal)) score += rule.score as number;
        else if (op === 'not_empty' && fieldVal) score += rule.score as number;
      }
    }

    // Activity bonus: +5 per activity, +10 per email open
    const actCount = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM activities WHERE contact_id = ?").bind(body!.contact_id).first<{ n: number }>();
    const emailOpens = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM email_events WHERE contact_id = ? AND type = 'opened'").bind(body!.contact_id).first<{ n: number }>();
    score += (actCount?.n || 0) * 5 + (emailOpens?.n || 0) * 10;

    // AI enhancement via Engine Runtime
    try {
      const resp = await c.env.ENGINE_RUNTIME.fetch('https://engine-runtime/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: `Score this lead: ${contact.first_name} ${contact.last_name}, title: ${contact.title || 'unknown'}, source: ${contact.source}, company: ${contact.company_id ? 'has company' : 'no company'}, email: ${contact.email ? 'yes' : 'no'}, activities: ${actCount?.n || 0}`, domain: 'sales', limit: 1 }),
      });
      if (resp.ok) {
        const data = await resp.json() as { engines?: { relevance_score?: number }[] };
        if (data.engines?.[0]?.relevance_score) score += Math.round(data.engines[0].relevance_score * 20);
      }
    } catch { /* Engine Runtime unavailable, use rule-based only */ }

    score = Math.min(100, Math.max(0, score));
    await c.env.DB.prepare("UPDATE contacts SET lead_score = ?, updated_at = ? WHERE id = ?").bind(score, nowISO(), body!.contact_id).run();
    return ok({ contact_id: body!.contact_id, score });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /lead-scoring/score', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// ANALYTICS
// ═══════════════════════════════════════════════════════════════════

app.get('/analytics/pipeline', async (c) => {
  const pipelineId = new URL(c.req.url).searchParams.get('pipeline_id');
  if (!pipelineId) return fail('pipeline_id required');

  try {
    const stages = await c.env.DB.prepare("SELECT ds.id, ds.name, ds.position, ds.probability, COUNT(d.id) AS deal_count, COALESCE(SUM(d.value), 0) AS total_value FROM deal_stages ds LEFT JOIN deals d ON ds.id = d.stage_id AND d.status = 'open' WHERE ds.pipeline_id = ? GROUP BY ds.id ORDER BY ds.position").bind(pipelineId).all();
    const wonDeals = await c.env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(value), 0) AS total FROM deals WHERE pipeline_id = ? AND status = 'won'").bind(pipelineId).first<{ n: number; total: number }>();
    const lostDeals = await c.env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(value), 0) AS total FROM deals WHERE pipeline_id = ? AND status = 'lost'").bind(pipelineId).first<{ n: number; total: number }>();
    const openValue = await c.env.DB.prepare("SELECT COALESCE(SUM(value), 0) AS total FROM deals WHERE pipeline_id = ? AND status = 'open'").bind(pipelineId).first<{ total: number }>();
    const weightedValue = await c.env.DB.prepare("SELECT COALESCE(SUM(d.value * ds.probability / 100), 0) AS total FROM deals d JOIN deal_stages ds ON d.stage_id = ds.id WHERE d.pipeline_id = ? AND d.status = 'open'").bind(pipelineId).first<{ total: number }>();

    return ok({
      stages: stages.results,
      won: { count: wonDeals?.n || 0, value: wonDeals?.total || 0 },
      lost: { count: lostDeals?.n || 0, value: lostDeals?.total || 0 },
      open_value: openValue?.total || 0,
      weighted_pipeline: weightedValue?.total || 0,
      win_rate: (wonDeals?.n && lostDeals?.n) ? Math.round((wonDeals.n / (wonDeals.n + lostDeals.n)) * 100) : 0,
    });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /analytics/pipeline', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/analytics/contacts', async (c) => {
  try {
    const byStatus = await c.env.DB.prepare("SELECT lead_status, COUNT(*) AS n FROM contacts GROUP BY lead_status").all();
    const bySource = await c.env.DB.prepare("SELECT source, COUNT(*) AS n FROM contacts GROUP BY source ORDER BY n DESC").all();
    const topScored = await c.env.DB.prepare("SELECT id, first_name, last_name, email, lead_score, lead_status FROM contacts WHERE lead_score > 0 ORDER BY lead_score DESC LIMIT 10").all();
    const total = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM contacts").first<{ n: number }>();
    const thisMonth = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM contacts WHERE created_at >= date('now', 'start of month')").first<{ n: number }>();

    return ok({
      total: total?.n || 0,
      this_month: thisMonth?.n || 0,
      by_status: byStatus.results,
      by_source: bySource.results,
      top_scored: topScored.results,
    });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /analytics/contacts', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/analytics/activity', async (c) => {
  try {
    const byType = await c.env.DB.prepare("SELECT type, COUNT(*) AS n FROM activities GROUP BY type ORDER BY n DESC").all();
    const thisWeek = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM activities WHERE created_at >= date('now', '-7 days')").first<{ n: number }>();
    const overdue = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM activities WHERE is_done = 0 AND due_date < date('now')").first<{ n: number }>();
    const upcoming = await c.env.DB.prepare("SELECT * FROM activities WHERE is_done = 0 AND due_date IS NOT NULL AND due_date >= date('now') ORDER BY due_date ASC LIMIT 10").all();

    return ok({
      by_type: byType.results,
      this_week: thisWeek?.n || 0,
      overdue: overdue?.n || 0,
      upcoming: upcoming.results,
    });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /analytics/activity', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/analytics/revenue', async (c) => {
  try {
    const monthly = await c.env.DB.prepare("SELECT strftime('%Y-%m', actual_close_date) AS month, SUM(value) AS revenue, COUNT(*) AS deals FROM deals WHERE status = 'won' AND actual_close_date IS NOT NULL GROUP BY month ORDER BY month DESC LIMIT 12").all();
    const avgDealSize = await c.env.DB.prepare("SELECT AVG(value) AS avg_value FROM deals WHERE status = 'won'").first<{ avg_value: number }>();
    const avgCycleTime = await c.env.DB.prepare("SELECT AVG(JULIANDAY(actual_close_date) - JULIANDAY(created_at)) AS avg_days FROM deals WHERE status = 'won' AND actual_close_date IS NOT NULL").first<{ avg_days: number }>();

    return ok({
      monthly: monthly.results,
      avg_deal_size: Math.round((avgDealSize?.avg_value || 0) * 100) / 100,
      avg_cycle_days: Math.round(avgCycleTime?.avg_days || 0),
    });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /analytics/revenue', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// IMPORT / EXPORT
// ═══════════════════════════════════════════════════════════════════

app.post('/import/contacts', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'contacts');
  if (err) return fail(err);
  const contacts = body!.contacts as Record<string, unknown>[];
  if (!Array.isArray(contacts)) return fail('contacts must be an array');
  if (contacts.length > 500) return fail('Max 500 contacts per import');

  const importId = uid();
  let imported = 0, skipped = 0, errors = 0;

  for (const contact of contacts) {
    try {
      if (!contact.first_name) { skipped++; continue; }
      const id = uid();
      const now = nowISO();
      await c.env.DB.prepare(
        "INSERT INTO contacts (id, first_name, last_name, email, phone, title, source, lead_status, company_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      ).bind(id, sanitize(contact.first_name as string, 100), sanitize((contact.last_name || '') as string, 100),
        sanitize((contact.email || '') as string, 200), sanitize((contact.phone || '') as string, 30),
        sanitize((contact.title || '') as string, 100), contact.source || 'import', 'new', contact.company_id || null, now, now).run();
      imported++;
    } catch {
      errors++;
    }
  }

  const importStatus = errors > 0 ? 'partial' : 'completed';
  try {
    await c.env.DB.prepare("INSERT INTO imports (id, type, total_rows, imported, skipped, errors, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(importId, 'contacts', contacts.length, imported, skipped, errors, importStatus, nowISO()).run();
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'POST /import/contacts (import log)', error: e?.message }));
  }
  log('info', 'Contacts imported', { importId, imported, skipped, errors });
  return ok({ import_id: importId, imported, skipped, errors });
});

app.get('/export/contacts', async (c) => {
  try {
    const rows = await c.env.DB.prepare("SELECT * FROM contacts ORDER BY created_at DESC LIMIT 5000").all();
    return ok({ contacts: rows.results, count: rows.results.length });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /export/contacts', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// ACTIVITY LOG
// ═══════════════════════════════════════════════════════════════════

app.get('/activity-log', async (c) => {
  const url = new URL(c.req.url);
  const { limit, offset } = paginate(url);
  const entityType = url.searchParams.get('entity_type');
  const entityId = url.searchParams.get('entity_id');

  let where = '1=1';
  const binds: unknown[] = [];
  if (entityType) { where += ' AND entity_type = ?'; binds.push(entityType); }
  if (entityId) { where += ' AND entity_id = ?'; binds.push(entityId); }

  binds.push(limit, offset);
  try {
    const rows = await c.env.DB.prepare(`SELECT * FROM activity_log WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(...binds).all();
    return ok({ log: rows.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-crm', message: 'D1 query failed', endpoint: 'GET /activity-log', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// CRON: Weekly Pipeline Digest (Monday 8am)
// ═══════════════════════════════════════════════════════════════════

async function cronHandler(env: Env): Promise<void> {
  log('info', 'Running weekly CRM digest');
  try {
    const openDeals = await env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(value), 0) AS total FROM deals WHERE status = 'open'").first<{ n: number; total: number }>();
    const wonThisWeek = await env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(value), 0) AS total FROM deals WHERE status = 'won' AND actual_close_date >= date('now', '-7 days')").first<{ n: number; total: number }>();
    const overdueActivities = await env.DB.prepare("SELECT COUNT(*) AS n FROM activities WHERE is_done = 0 AND due_date < date('now')").first<{ n: number }>();
    const newContacts = await env.DB.prepare("SELECT COUNT(*) AS n FROM contacts WHERE created_at >= date('now', '-7 days')").first<{ n: number }>();

    const digest = `CRM Weekly: ${openDeals?.n || 0} open deals ($${openDeals?.total || 0}), ${wonThisWeek?.n || 0} won this week ($${wonThisWeek?.total || 0}), ${overdueActivities?.n || 0} overdue activities, ${newContacts?.n || 0} new contacts`;
    log('info', digest);

    // Post to Shared Brain
    try {
      await env.SHARED_BRAIN.fetch('https://shared-brain/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ instance_id: 'echo-crm', role: 'system', content: digest, importance: 6, tags: ['crm', 'digest'] }),
      });
    } catch (e) { log('warn', 'Shared Brain digest ingest failed', { error: String(e) }); }
  } catch (e) {
    log('error', 'Cron failed', { error: String(e) });
  }
}

// ═══════════════════════════════════════════════════════════════════
// STRIPE PAYMENTS
// ═══════════════════════════════════════════════════════════════════

app.get('/plans', (c) => ok({ plans: CRM_PLANS, service: 'echo-crm' }));

app.post('/webhooks/stripe', async (c) => {
  const body = await c.req.text();
  const sig = c.req.header('Stripe-Signature') || '';
  const secret = c.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) return fail('Webhook secret not configured', 500);
  const valid = await verifyStripeSignature(body, sig, secret);
  if (!valid) { log('warn', 'Stripe webhook signature invalid'); return fail('Invalid signature', 401); }
  try {
    const event = JSON.parse(body) as { type: string; data: { object: Record<string, unknown> } };
    log('info', 'Stripe webhook received', { type: event.type });
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const tenantId = (session.metadata as Record<string, string>)?.tenant_id;
      const planId = (session.metadata as Record<string, string>)?.plan_id;
      if (tenantId && planId) {
        await c.env.DB.prepare("UPDATE tenants SET plan = ?, stripe_customer_id = ?, stripe_subscription_id = ?, updated_at = ? WHERE id = ?")
          .bind(planId, session.customer || null, session.subscription || null, nowISO(), tenantId).run();
        log('info', 'Tenant upgraded via Stripe', { tenantId, planId });
      }
    } else if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      const customerId = sub.customer as string;
      if (customerId) {
        await c.env.DB.prepare("UPDATE tenants SET plan = 'free', stripe_subscription_id = NULL, updated_at = ? WHERE stripe_customer_id = ?")
          .bind(nowISO(), customerId).run();
        log('info', 'Tenant downgraded to free', { customerId });
      }
    }
    return ok({ received: true });
  } catch (e: unknown) {
    log('error', 'Stripe webhook processing failed', { error: String(e) });
    return fail('Webhook processing error', 500);
  }
});

app.post('/plans/upgrade', async (c) => {
  const body = await c.req.json().catch(() => null) as Record<string, unknown> | null;
  const err = requireBody(body, 'tenant_id', 'plan_id');
  if (err) return fail(err);
  const plan = CRM_PLANS.find(p => p.id === body!.plan_id);
  if (!plan) return fail('Invalid plan_id');
  if (!c.env.STRIPE_SECRET_KEY) return fail('Stripe not configured', 500);
  try {
    const resp = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${c.env.STRIPE_SECRET_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        'mode': 'subscription',
        'success_url': 'https://echo-ept.com/dashboard?upgrade=success',
        'cancel_url': 'https://echo-ept.com/dashboard?upgrade=cancel',
        'line_items[0][price_data][currency]': 'usd',
        'line_items[0][price_data][unit_amount]': String(Math.round(plan.price * 100)),
        'line_items[0][price_data][recurring][interval]': 'month',
        'line_items[0][price_data][product_data][name]': `Echo CRM - ${plan.name}`,
        'metadata[tenant_id]': String(body!.tenant_id),
        'metadata[plan_id]': plan.id,
      }).toString(),
    });
    const session = await resp.json() as Record<string, unknown>;
    if (!resp.ok) { log('error', 'Stripe checkout failed', { error: session }); return fail('Stripe checkout creation failed', 500); }
    return ok({ checkout_url: session.url, session_id: session.id });
  } catch (e: unknown) {
    log('error', 'Stripe API error', { error: String(e) });
    return fail('Payment service unavailable', 503);
  }
});

app.post('/admin/migrate-stripe', async (c) => {
  try {
    await c.env.DB.prepare(`CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY, name TEXT, plan TEXT DEFAULT 'free',
      stripe_customer_id TEXT, stripe_subscription_id TEXT,
      created_at TEXT, updated_at TEXT
    )`).run();
    log('info', 'Stripe migration complete');
    return ok({ migrated: true, tables: ['tenants'] });
  } catch (e: unknown) {
    log('error', 'Stripe migration failed', { error: String(e) });
    return fail('Migration failed', 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════════

app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  log('error', 'Unhandled request error', { error: err.message, stack: err.stack });
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(cronHandler(env));
  },
};
