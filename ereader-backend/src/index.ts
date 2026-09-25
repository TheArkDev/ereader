import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { hashPassword, verifyPassword, signToken, verifyToken } from './auth';

export interface Env {
  DB: D1Database;
  FILES: R2Bucket;
  KV: KVNamespace;
  JWT_SECRET: string;
}

type Vars = { userId: string; email: string };

const app = new Hono<{ Bindings: Env; Variables: Vars }>();

app.use('*', cors());

// ---------- Auth middleware ----------
async function requireAuth(c: any, next: any) {
  const authHeader = c.req.header('Authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return c.json({ error: 'Missing token' }, 401);

  // Check revocation list (logout) in KV.
  const revoked = await c.env.KV.get(`revoked:${token}`);
  if (revoked) return c.json({ error: 'Token revoked' }, 401);

  const payload = await verifyToken(token, c.env.JWT_SECRET);
  if (!payload) return c.json({ error: 'Invalid or expired token' }, 401);

  c.set('userId', payload.userId);
  c.set('email', payload.email);
  c.set('_token', token);
  await next();
}

// ---------- Auth routes ----------
app.post('/auth/signup', async (c) => {
  const body = await c.req.json<{ email?: string; password?: string; displayName?: string }>();
  const email = body.email?.trim().toLowerCase();
  const password = body.password;
  if (!email || !password || password.length < 8) {
    return c.json({ error: 'Valid email and password (min 8 chars) required' }, 400);
  }

  const existing = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (existing) return c.json({ error: 'Email already registered' }, 409);

  const id = crypto.randomUUID();
  const { hash, salt } = await hashPassword(password);

  await c.env.DB.prepare(
    'INSERT INTO users (id, email, password_hash, password_salt, display_name) VALUES (?, ?, ?, ?, ?)'
  )
    .bind(id, email, hash, salt, body.displayName ?? null)
    .run();

  const token = await signToken(id, email, c.env.JWT_SECRET);
  return c.json({ token, user: { id, email, displayName: body.displayName ?? null } });
});

app.post('/auth/login', async (c) => {
  const body = await c.req.json<{ email?: string; password?: string }>();
  const email = body.email?.trim().toLowerCase();
  const password = body.password;
  if (!email || !password) return c.json({ error: 'Email and password required' }, 400);

  const user = await c.env.DB.prepare(
    'SELECT id, email, password_hash, password_salt, display_name FROM users WHERE email = ?'
  )
    .bind(email)
    .first<{ id: string; email: string; password_hash: string; password_salt: string; display_name: string | null }>();

  if (!user) return c.json({ error: 'Invalid credentials' }, 401);

  const ok = await verifyPassword(password, user.password_hash, user.password_salt);
  if (!ok) return c.json({ error: 'Invalid credentials' }, 401);

  const token = await signToken(user.id, user.email, c.env.JWT_SECRET);
  return c.json({ token, user: { id: user.id, email: user.email, displayName: user.display_name } });
});

app.post('/auth/logout', requireAuth, async (c) => {
  const token = c.get('_token' as any) as string;
  // Store until natural JWT expiry (30d) so it can't be replayed.
  await c.env.KV.put(`revoked:${token}`, '1', { expirationTtl: 60 * 60 * 24 * 30 });
  return c.json({ ok: true });
});

app.get('/auth/me', requireAuth, async (c) => {
  const user = await c.env.DB.prepare('SELECT id, email, display_name FROM users WHERE id = ?')
    .bind(c.get('userId'))
    .first();
  return c.json({ user });
});

// ---------- Book routes ----------
app.get('/books', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT id, title, author, description, format, cover_key, created_at FROM books ORDER BY created_at DESC'
  ).all();
  return c.json({ books: results });
});

app.get('/books/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const book = await c.env.DB.prepare(
    'SELECT id, title, author, description, format, cover_key, file_size, created_at FROM books WHERE id = ?'
  )
    .bind(id)
    .first();
  if (!book) return c.json({ error: 'Not found' }, 404);
  return c.json({ book });
});

// Stream the actual book file (pdf/epub) from R2, with byte-range support
// so viewers can seek without downloading the whole file up front.
app.get('/books/:id/file', requireAuth, async (c) => {
  const id = c.req.param('id');
  const book = await c.env.DB.prepare('SELECT file_key, format FROM books WHERE id = ?')
    .bind(id)
    .first<{ file_key: string; format: string }>();
  if (!book) return c.json({ error: 'Not found' }, 404);

  return streamR2Object(c, book.file_key, book.format === 'pdf' ? 'application/pdf' : 'application/epub+zip');
});

// Stream the cover image from R2.
app.get('/books/:id/cover', requireAuth, async (c) => {
  const id = c.req.param('id');
  const book = await c.env.DB.prepare('SELECT cover_key FROM books WHERE id = ?')
    .bind(id)
    .first<{ cover_key: string | null }>();
  if (!book?.cover_key) return c.json({ error: 'No cover' }, 404);

  return streamR2Object(c, book.cover_key, 'image/jpeg');
});

async function streamR2Object(c: any, key: string, defaultContentType: string) {
  const env: Env = c.env;
  const rangeHeader = c.req.header('Range');

  const options: R2GetOptions = {};
  if (rangeHeader) {
    const match = /bytes=(\d+)-(\d*)/.exec(rangeHeader);
    if (match) {
      const start = parseInt(match[1], 10);
      const end = match[2] ? parseInt(match[2], 10) : undefined;
      options.range = end !== undefined ? { offset: start, length: end - start + 1 } : { offset: start };
    }
  }

  const object = await env.FILES.get(key, options);
  if (!object) return c.json({ error: 'File not found in storage' }, 404);

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('etag', object.httpEtag);
  headers.set('accept-ranges', 'bytes');
  if (!headers.get('content-type')) headers.set('content-type', defaultContentType);

  const status = rangeHeader && 'range' in object ? 206 : 200;
  if (status === 206 && (object as any).range) {
    const r = (object as any).range;
    const total = object.size;
    headers.set('content-range', `bytes ${r.offset}-${r.offset + (r.length ?? total - r.offset) - 1}/${total}`);
  }

  return new Response(object.body, { status, headers });
}

// ---------- Reading progress ----------
app.get('/progress/:bookId', requireAuth, async (c) => {
  const row = await c.env.DB.prepare('SELECT position, updated_at FROM reading_progress WHERE user_id = ? AND book_id = ?')
    .bind(c.get('userId'), c.req.param('bookId'))
    .first();
  return c.json({ progress: row ?? null });
});

app.put('/progress/:bookId', requireAuth, async (c) => {
  const body = await c.req.json<{ position: string }>();
  await c.env.DB.prepare(
    `INSERT INTO reading_progress (user_id, book_id, position, updated_at)
     VALUES (?, ?, ?, datetime('now'))
     ON CONFLICT(user_id, book_id) DO UPDATE SET position = excluded.position, updated_at = datetime('now')`
  )
    .bind(c.get('userId'), c.req.param('bookId'), body.position)
    .run();
  return c.json({ ok: true });
});

app.get('/', (c) => c.text('ereader API is running'));

export default app;
