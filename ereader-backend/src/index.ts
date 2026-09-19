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

// Must run after requireAuth. Looks up is_admin fresh from D1 on every
// request rather than trusting anything from the JWT, so revoking admin
// takes effect immediately without needing new tokens.
async function requireAdmin(c: any, next: any) {
  const user = await c.env.DB.prepare('SELECT is_admin FROM users WHERE id = ?')
    .bind(c.get('userId'))
    .first<{ is_admin: number }>();
  if (!user || user.is_admin !== 1) return c.json({ error: 'Admin access required' }, 403);
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
  return c.json({ token, user: { id, email, displayName: body.displayName ?? null, is_admin: false } });
});

app.post('/auth/login', async (c) => {
  const body = await c.req.json<{ email?: string; password?: string }>();
  const email = body.email?.trim().toLowerCase();
  const password = body.password;
  if (!email || !password) return c.json({ error: 'Email and password required' }, 400);

  const user = await c.env.DB.prepare(
    'SELECT id, email, password_hash, password_salt, display_name, is_admin FROM users WHERE email = ?'
  )
    .bind(email)
    .first<{
      id: string;
      email: string;
      password_hash: string;
      password_salt: string;
      display_name: string | null;
      is_admin: number;
    }>();

  if (!user) return c.json({ error: 'Invalid credentials' }, 401);

  const ok = await verifyPassword(password, user.password_hash, user.password_salt);
  if (!ok) return c.json({ error: 'Invalid credentials' }, 401);

  const token = await signToken(user.id, user.email, c.env.JWT_SECRET);
  return c.json({
    token,
    user: { id: user.id, email: user.email, displayName: user.display_name, is_admin: user.is_admin === 1 },
  });
});

app.post('/auth/logout', requireAuth, async (c) => {
  const token = c.get('_token' as any) as string;
  // Store until natural JWT expiry (30d) so it can't be replayed.
  await c.env.KV.put(`revoked:${token}`, '1', { expirationTtl: 60 * 60 * 24 * 30 });
  return c.json({ ok: true });
});

app.get('/auth/me', requireAuth, async (c) => {
  const user = await c.env.DB.prepare('SELECT id, email, display_name, is_admin FROM users WHERE id = ?')
    .bind(c.get('userId'))
    .first<{ id: string; email: string; display_name: string | null; is_admin: number }>();
  if (!user) return c.json({ error: 'Not found' }, 404);
  return c.json({ user: { ...user, is_admin: user.is_admin === 1 } });
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

// ---------- Admin: book management ----------
// All routes below require the caller to be an admin (see requireAdmin above).

// Upload a new book. Expects multipart/form-data:
//   title (required), author, description, format ('pdf' | 'epub', required)
//   bookFile (required, the actual .pdf/.epub)
//   coverFile (optional image)
app.post('/admin/books', requireAuth, requireAdmin, async (c) => {
  const form = await c.req.formData();

  const title = (form.get('title') as string | null)?.trim();
  const author = (form.get('author') as string | null)?.trim() || null;
  const description = (form.get('description') as string | null)?.trim() || null;
  const format = form.get('format') as string | null;
  const bookFile = form.get('bookFile') as File | null;
  const coverFile = form.get('coverFile') as File | null;

  if (!title) return c.json({ error: 'title is required' }, 400);
  if (format !== 'pdf' && format !== 'epub') return c.json({ error: "format must be 'pdf' or 'epub'" }, 400);
  if (!bookFile) return c.json({ error: 'bookFile is required' }, 400);

  const id = crypto.randomUUID();
  const fileKey = `books/${id}.${format}`;
  const bookBytes = await bookFile.arrayBuffer();

  await c.env.FILES.put(fileKey, bookBytes, {
    httpMetadata: { contentType: format === 'pdf' ? 'application/pdf' : 'application/epub+zip' },
  });

  let coverKey: string | null = null;
  if (coverFile && coverFile.size > 0) {
    coverKey = `covers/${id}.jpg`;
    await c.env.FILES.put(coverKey, await coverFile.arrayBuffer(), {
      httpMetadata: { contentType: coverFile.type || 'image/jpeg' },
    });
  }

  await c.env.DB.prepare(
    `INSERT INTO books (id, title, author, description, format, file_key, cover_key, file_size)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(id, title, author, description, format, fileKey, coverKey, bookBytes.byteLength)
    .run();

  return c.json({
    book: { id, title, author, description, format, cover_key: coverKey, file_size: bookBytes.byteLength },
  });
});

// Edit a book: metadata (title/author/description), and optionally replace
// its cover image and/or the book file itself. multipart/form-data — any
// field can be omitted to leave that part unchanged.
app.patch('/admin/books/:id', requireAuth, requireAdmin, async (c) => {
  const id = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT file_key, cover_key, format FROM books WHERE id = ?')
    .bind(id)
    .first<{ file_key: string; cover_key: string | null; format: string }>();
  if (!existing) return c.json({ error: 'Not found' }, 404);

  const form = await c.req.formData();
  const title = (form.get('title') as string | null)?.trim() || null;
  const author = (form.get('author') as string | null)?.trim() || null;
  const description = (form.get('description') as string | null)?.trim() || null;
  const bookFile = form.get('bookFile') as File | null;
  const coverFile = form.get('coverFile') as File | null;

  let fileSizeUpdate: number | null = null;
  if (bookFile && bookFile.size > 0) {
    // Reuse the existing key (same extension/format) so nothing else needs updating.
    const bytes = await bookFile.arrayBuffer();
    await c.env.FILES.put(existing.file_key, bytes, {
      httpMetadata: { contentType: existing.format === 'pdf' ? 'application/pdf' : 'application/epub+zip' },
    });
    fileSizeUpdate = bytes.byteLength;
  }

  let coverKeyUpdate: string | null | undefined = undefined; // undefined = don't touch
  if (coverFile && coverFile.size > 0) {
    const coverKey = existing.cover_key ?? `covers/${id}.jpg`;
    await c.env.FILES.put(coverKey, await coverFile.arrayBuffer(), {
      httpMetadata: { contentType: coverFile.type || 'image/jpeg' },
    });
    coverKeyUpdate = coverKey;
  }

  await c.env.DB.prepare(
    `UPDATE books SET
       title = COALESCE(?, title),
       author = ?,
       description = ?,
       file_size = COALESCE(?, file_size),
       cover_key = COALESCE(?, cover_key)
     WHERE id = ?`
  )
    .bind(title, author, description, fileSizeUpdate, coverKeyUpdate ?? null, id)
    .run();

  return c.json({ ok: true });
});

// Delete a book: removes the D1 row and its R2 objects (file + cover).
app.delete('/admin/books/:id', requireAuth, requireAdmin, async (c) => {
  const id = c.req.param('id');
  const book = await c.env.DB.prepare('SELECT file_key, cover_key FROM books WHERE id = ?')
    .bind(id)
    .first<{ file_key: string; cover_key: string | null }>();
  if (!book) return c.json({ error: 'Not found' }, 404);

  await c.env.FILES.delete(book.file_key);
  if (book.cover_key) await c.env.FILES.delete(book.cover_key);

  await c.env.DB.prepare('DELETE FROM reading_progress WHERE book_id = ?').bind(id).run();
  await c.env.DB.prepare('DELETE FROM books WHERE id = ?').bind(id).run();

  return c.json({ ok: true });
});

// ---------- Reading progress ----------
app.get('/progress', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT book_id, position, updated_at FROM reading_progress WHERE user_id = ?'
  )
    .bind(c.get('userId'))
    .all();
  return c.json({ progress: results });
});

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
