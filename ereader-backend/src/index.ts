import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { hashPassword, verifyPassword, signToken, verifyToken } from './auth';
import { extractEpubCover } from './epubCover';

export interface Env {
  DB: D1Database;
  FILES: R2Bucket;
  KV: KVNamespace;
  JWT_SECRET: string;
  RESEND_API_KEY: string;
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

  // Checked on every request (not just at login) so disabling an account
  // takes effect immediately, even for a token issued before the disable.
  const user = await c.env.DB.prepare('SELECT is_disabled FROM users WHERE id = ?')
    .bind(payload.userId)
    .first<{ is_disabled: number }>();
  if (!user || user.is_disabled === 1) return c.json({ error: 'Account disabled' }, 403);

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
    'SELECT id, email, password_hash, password_salt, display_name, is_admin, is_disabled FROM users WHERE email = ?'
  )
    .bind(email)
    .first<{
      id: string;
      email: string;
      password_hash: string;
      password_salt: string;
      display_name: string | null;
      is_admin: number;
      is_disabled: number;
    }>();

  if (!user) return c.json({ error: 'Invalid credentials' }, 401);

  const ok = await verifyPassword(password, user.password_hash, user.password_salt);
  if (!ok) return c.json({ error: 'Invalid credentials' }, 401);

  if (user.is_disabled === 1) return c.json({ error: 'This account has been disabled.' }, 403);

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

app.patch('/auth/me', requireAuth, async (c) => {
  const body = await c.req.json<{ displayName?: string }>();
  const displayName = body.displayName?.trim();
  await c.env.DB.prepare('UPDATE users SET display_name = COALESCE(?, display_name) WHERE id = ?')
    .bind(displayName && displayName.length > 0 ? displayName : null, c.get('userId'))
    .run();
  return c.json({ ok: true });
});

app.post('/auth/change-password', requireAuth, async (c) => {
  const body = await c.req.json<{ currentPassword?: string; newPassword?: string }>();
  if (!body.currentPassword || !body.newPassword || body.newPassword.length < 8) {
    return c.json({ error: 'currentPassword and a newPassword (min 8 chars) are required' }, 400);
  }

  const user = await c.env.DB.prepare('SELECT password_hash, password_salt FROM users WHERE id = ?')
    .bind(c.get('userId'))
    .first<{ password_hash: string; password_salt: string }>();
  if (!user) return c.json({ error: 'Not found' }, 404);

  const ok = await verifyPassword(body.currentPassword, user.password_hash, user.password_salt);
  if (!ok) return c.json({ error: 'Current password is incorrect' }, 401);

  const { hash, salt } = await hashPassword(body.newPassword);
  await c.env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?')
    .bind(hash, salt, c.get('userId'))
    .run();
  return c.json({ ok: true });
});

// ---------- Password reset ----------
// Flow: app calls POST /auth/forgot-password -> we email a link that opens
// GET /reset-password?token=... (a plain HTML page served by this same
// Worker, since the app has no custom domain to deep-link into) -> the
// person sets a new password there -> POST /reset-password completes it.
// Reset tokens live in KV with a 1-hour TTL and are single-use.

async function sendEmail(env: Env, to: string, subject: string, html: string): Promise<void> {
  console.log(`[sendEmail] calling Resend API, key present: ${env.RESEND_API_KEY ? 'yes (' + env.RESEND_API_KEY.slice(0, 5) + '...)' : 'NO — RESEND_API_KEY IS EMPTY'}`);
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        // Was 'ereader <onboarding@resend.dev>' (Resend's shared testing
        // sender, which only delivers to your own Resend signup email —
        // that's why early reset emails silently never arrived for other
        // accounts). Now using the verified dominionlib.dpdns.org domain,
        // which can send to any recipient.
        from: 'ereader <noreply@dominionlib.dpdns.org>',
        to,
        subject,
        html,
      }),
    });
    const responseText = await res.text();
    if (!res.ok) {
      console.error(`[sendEmail] Resend API error: status=${res.status} body=${responseText}`);
    } else {
      console.log(`[sendEmail] Resend accepted the request: status=${res.status} body=${responseText}`);
    }
  } catch (err) {
    console.error(`[sendEmail] fetch() to Resend threw before getting any response: ${err}`);
  }
}

app.post('/auth/forgot-password', async (c) => {
  const body = await c.req.json<{ email?: string }>();
  const email = body.email?.trim().toLowerCase();
  console.log(`[forgot-password] request for: ${email ?? '(empty)'}`);

  // Always respond the same way whether or not the email exists, so this
  // endpoint can't be used to discover which emails are registered.
  const genericResponse = c.json({ message: 'If that email is registered, a reset link has been sent.' });
  if (!email) {
    console.log('[forgot-password] no email in request body — stopping here');
    return genericResponse;
  }

  const user = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first<{ id: string }>();
  if (!user) {
    console.log(`[forgot-password] no user found for "${email}" — stopping here (this is the #1 suspect if no email ever arrives)`);
    return genericResponse;
  }

  console.log(`[forgot-password] user found (id=${user.id}), generating token and emailing`);
  const token = crypto.randomUUID();
  await c.env.KV.put(`reset:${token}`, user.id, { expirationTtl: 3600 }); // 1 hour

  const resetUrl = `${new URL(c.req.url).origin}/reset-password?token=${token}`;
  await sendEmail(
    c.env,
    email,
    'Reset your ereader password',
    `<p>Someone requested a password reset for this email's ereader account.</p>
     <p><a href="${resetUrl}">Click here to set a new password</a> (link expires in 1 hour).</p>
     <p>If you didn't request this, you can safely ignore this email.</p>`
  );

  return genericResponse;
});

const RESET_PAGE_STYLES = `
  body { font-family: Georgia, serif; background: #FBF8F3; color: #1B1B1F; display: flex;
         justify-content: center; padding: 48px 20px; }
  .card { max-width: 380px; width: 100%; }
  h1 { font-size: 22px; margin-bottom: 8px; }
  p { color: #5c5850; font-size: 14px; }
  input { width: 100%; padding: 12px 14px; margin-top: 6px; margin-bottom: 16px; border-radius: 10px;
          border: 1px solid rgba(0,0,0,0.15); font-size: 15px; box-sizing: border-box; }
  label { font-size: 13px; font-weight: 600; }
  button { width: 100%; padding: 14px; border-radius: 10px; border: none; background: #5E3B26;
           color: white; font-size: 15px; font-weight: 600; cursor: pointer; }
  .error { color: #b3261e; font-size: 13px; margin-bottom: 12px; }
`;

app.get('/reset-password', async (c) => {
  const token = c.req.query('token') ?? '';
  const userId = token ? await c.env.KV.get(`reset:${token}`) : null;

  if (!userId) {
    return c.html(`<html><head><style>${RESET_PAGE_STYLES}</style></head><body><div class="card">
      <h1>Link expired</h1>
      <p>This password reset link is invalid or has expired. Go back to the app and request a new one.</p>
    </div></body></html>`);
  }

  return c.html(`<html><head><meta name="viewport" content="width=device-width, initial-scale=1">
    <style>${RESET_PAGE_STYLES}</style></head><body><div class="card">
    <h1>Set a new password</h1>
    <p>Choose a new password for your ereader account.</p>
    <form method="POST" action="/reset-password">
      <input type="hidden" name="token" value="${token}">
      <label>New password</label>
      <input type="password" name="password" minlength="8" required>
      <button type="submit">Reset password</button>
    </form>
  </div></body></html>`);
});

app.post('/reset-password', async (c) => {
  const form = await c.req.formData();
  const token = form.get('token') as string | null;
  const password = form.get('password') as string | null;

  const userId = token ? await c.env.KV.get(`reset:${token}`) : null;

  if (!userId) {
    return c.html(`<html><head><style>${RESET_PAGE_STYLES}</style></head><body><div class="card">
      <h1>Link expired</h1><p>Go back to the app and request a new reset link.</p>
    </div></body></html>`);
  }
  if (!password || password.length < 8) {
    return c.html(`<html><head><style>${RESET_PAGE_STYLES}</style></head><body><div class="card">
      <h1>Password too short</h1><p>Use the link in your email again and choose a password with at least 8 characters.</p>
    </div></body></html>`);
  }

  const { hash, salt } = await hashPassword(password);
  await c.env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?')
    .bind(hash, salt, userId)
    .run();
  await c.env.KV.delete(`reset:${token}`); // single-use

  return c.html(`<html><head><style>${RESET_PAGE_STYLES}</style></head><body><div class="card">
    <h1>Password updated</h1><p>You can now log in with your new password in the app.</p>
  </div></body></html>`);
});

// ---------- Book routes ----------
// Book listing. Everything is optional, so old callers that send no
// parameters still get the whole library exactly as before:
//   q, category        – filters (search is title/author, case-insensitive)
//   ids                – comma-separated book ids (max 80), for fetching specific books
//   sort               – newest (default) | title | author | random
//   coverFirst=1       – books without a cover first (admin tooling)
//   limit, offset      – paging (limit capped at 90); response then includes `total`
const MAX_PAGE = 90;
const MAX_IDS_PARAM = 80;

app.get('/books', requireAuth, async (c) => {
  const q = c.req.query('q')?.trim();
  const category = c.req.query('category')?.trim();
  const sort = c.req.query('sort') ?? 'newest';
  const coverFirst = c.req.query('coverFirst') === '1';
  const idsParam = c.req.query('ids');

  const limitNum = parseInt(c.req.query('limit') ?? '', 10);
  const offsetNum = parseInt(c.req.query('offset') ?? '', 10);
  const limit = Number.isFinite(limitNum) && limitNum > 0 ? Math.min(limitNum, MAX_PAGE) : null;
  const offset = Number.isFinite(offsetNum) && offsetNum > 0 ? offsetNum : 0;

  const conditions: string[] = ['deleted_at IS NULL'];
  const params: unknown[] = [];

  if (q) {
    conditions.push('(LOWER(title) LIKE ? OR LOWER(author) LIKE ?)');
    const like = `%${q.toLowerCase()}%`;
    params.push(like, like);
  }
  if (category) {
    conditions.push('category = ?');
    params.push(category);
  }
  if (idsParam) {
    const wanted = idsParam.split(',').map((i) => i.trim()).filter((i) => i.length > 0);
    if (wanted.length === 0 || wanted.length > MAX_IDS_PARAM) {
      return c.json({ error: `ids must contain 1–${MAX_IDS_PARAM} book ids` }, 400);
    }
    conditions.push(`id IN (${wanted.map(() => '?').join(',')})`);
    params.push(...wanted);
  }
  const where = conditions.length ? ' WHERE ' + conditions.join(' AND ') : '';

  const orderParts: string[] = [];
  if (coverFirst) orderParts.push('(cover_key IS NOT NULL) ASC'); // 0 = no cover, so those come first
  switch (sort) {
    case 'title':
      orderParts.push('LOWER(title) ASC');
      break;
    case 'author':
      orderParts.push("(author IS NULL OR author = '') ASC", 'LOWER(author) ASC'); // no author last
      break;
    case 'random':
      orderParts.push('RANDOM()');
      break;
    default:
      orderParts.push('created_at DESC');
  }
  orderParts.push('id ASC'); // stable tie-break so pages never overlap or skip

  let sql = `SELECT id, title, author, description, format, cover_key, category, created_at FROM books${where} ORDER BY ${orderParts.join(', ')}`;
  const pageParams = [...params];
  if (limit !== null) {
    sql += ' LIMIT ? OFFSET ?';
    pageParams.push(limit, offset);
  }

  const { results } = await c.env.DB.prepare(sql).bind(...pageParams).all();

  let total = results.length;
  if (limit !== null) {
    const countRow = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM books${where}`)
      .bind(...params)
      .first<{ n: number }>();
    total = countRow?.n ?? results.length;
  }

  // Search-hit tracking: only for real text searches, only on the first page
  // (so scrolling doesn't inflate counts), and capped to stay under D1's
  // ~100 bound-parameter limit per statement.
  if (q && offset === 0 && results.length > 0) {
    const hitIds = results.slice(0, MAX_PAGE).map((r: any) => r.id as string);
    const placeholders = hitIds.map(() => '?').join(',');
    c.executionCtx.waitUntil(
      c.env.DB.prepare(`UPDATE books SET search_hit_count = search_hit_count + 1 WHERE id IN (${placeholders})`)
        .bind(...hitIds)
        .run()
    );
  }

  return c.json({ books: results, total });
});

// The book of the day, picked server-side so the app never needs the whole
// library just to choose one. `seed` is the caller's local date (YYYYMMDD),
// so it changes at the reader's midnight rather than UTC's.
app.get('/books/daily', requireAuth, async (c) => {
  const countRow = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM books WHERE deleted_at IS NULL').first<{ n: number }>();
  const total = countRow?.n ?? 0;
  if (total === 0) return c.json({ book: null });

  const seedNum = parseInt(c.req.query('seed') ?? '', 10);
  const now = new Date();
  const seed = Number.isFinite(seedNum) && seedNum > 0
    ? seedNum
    : now.getUTCFullYear() * 10000 + (now.getUTCMonth() + 1) * 100 + now.getUTCDate();

  const book = await c.env.DB.prepare(
    'SELECT id, title, author, description, format, cover_key, category, created_at FROM books WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 1 OFFSET ?'
  )
    .bind(seed % total)
    .first();
  return c.json({ book: book ?? null });
});

// Called by the app once when a book is opened in the reader. Best-effort —
// the app doesn't wait on this or fail if it errors. Bumps the lifetime
// counter AND logs a dated event, which is what makes "most read this week"
// on the admin dashboard possible.
app.post('/books/:id/view', requireAuth, async (c) => {
  const id = c.req.param('id');
  const result = await c.env.DB.prepare('UPDATE books SET view_count = view_count + 1 WHERE id = ? AND deleted_at IS NULL')
    .bind(id)
    .run();
  if ((result.meta?.changes ?? 0) > 0) {
    await c.env.DB.prepare('INSERT INTO book_views (book_id, user_id) VALUES (?, ?)').bind(id, c.get('userId')).run();
  }
  return c.json({ ok: true });
});

// Distinct category list, for populating filter chips in the app.
app.get('/categories', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT DISTINCT category FROM books WHERE category IS NOT NULL AND category != '' AND deleted_at IS NULL ORDER BY category"
  ).all();
  return c.json({ categories: results.map((r: any) => r.category as string) });
});

app.get('/books/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const book = await c.env.DB.prepare(
    'SELECT id, title, author, description, format, cover_key, category, file_size, created_at FROM books WHERE id = ? AND deleted_at IS NULL'
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
  const book = await c.env.DB.prepare('SELECT file_key, format FROM books WHERE id = ? AND deleted_at IS NULL')
    .bind(id)
    .first<{ file_key: string; format: string }>();
  if (!book) return c.json({ error: 'Not found' }, 404);

  return streamR2Object(c, book.file_key, book.format === 'pdf' ? 'application/pdf' : 'application/epub+zip');
});

// Stream the cover image from R2.
app.get('/books/:id/cover', requireAuth, async (c) => {
  const id = c.req.param('id');
  const book = await c.env.DB.prepare('SELECT cover_key FROM books WHERE id = ? AND deleted_at IS NULL')
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
//   title (required), author, description, category, format ('pdf' | 'epub', required)
//   bookFile (required, the actual .pdf/.epub)
//   coverFile (optional image)
app.post('/admin/books', requireAuth, requireAdmin, async (c) => {
  const form = await c.req.formData();

  const title = (form.get('title') as string | null)?.trim();
  const author = (form.get('author') as string | null)?.trim() || null;
  const description = (form.get('description') as string | null)?.trim() || null;
  const category = (form.get('category') as string | null)?.trim() || null;
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
  } else if (format === 'epub') {
    // No cover was supplied — most real EPUBs declare one in their own
    // metadata, so try pulling that out automatically before giving up.
    const extracted = extractEpubCover(new Uint8Array(bookBytes));
    if (extracted) {
      const ext = extracted.contentType === 'image/png' ? 'png' : 'jpg';
      coverKey = `covers/${id}.${ext}`;
      await c.env.FILES.put(coverKey, extracted.bytes, { httpMetadata: { contentType: extracted.contentType } });
    }
  }

  await c.env.DB.prepare(
    `INSERT INTO books (id, title, author, description, category, format, file_key, cover_key, file_size)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(id, title, author, description, category, format, fileKey, coverKey, bookBytes.byteLength)
    .run();

  return c.json({
    book: { id, title, author, description, category, format, cover_key: coverKey, file_size: bookBytes.byteLength },
  });
});

// Edit a book: metadata (title/author/description/category), and optionally
// replace its cover image and/or the book file itself. multipart/form-data.
//
// Duplicate guard: if another book (different id) already has the same
// title AND the same author, case-insensitively, the update is REJECTED
// with 409 rather than saved — the caller offers deleting the existing
// duplicate instead, then retries.
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
  const category = (form.get('category') as string | null)?.trim() || null;
  const bookFile = form.get('bookFile') as File | null;
  const coverFile = form.get('coverFile') as File | null;

  if (title) {
    const dupe = await c.env.DB.prepare(
      `SELECT id, title, author FROM books
       WHERE id != ? AND deleted_at IS NULL AND LOWER(title) = LOWER(?) AND LOWER(COALESCE(author, '')) = LOWER(COALESCE(?, ''))`
    )
      .bind(id, title, author ?? '')
      .first<{ id: string; title: string; author: string | null }>();

    if (dupe) {
      return c.json(
        {
          error: 'duplicate',
          message: `"${dupe.title}"${dupe.author ? ` by ${dupe.author}` : ''} already exists in the library.`,
          duplicate: { id: dupe.id, title: dupe.title, author: dupe.author },
        },
        409
      );
    }
  }

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
       category = ?,
       file_size = COALESCE(?, file_size),
       cover_key = COALESCE(?, cover_key)
     WHERE id = ?`
  )
    .bind(title, author, description, category, fileSizeUpdate, coverKeyUpdate ?? null, id)
    .run();

  return c.json({ ok: true });
});

// "Delete" now moves a book to the trash (hidden from readers, restorable for
// 30 days). Files and reading data are kept until it's purged for good.
app.delete('/admin/books/:id', requireAuth, requireAdmin, async (c) => {
  const id = c.req.param('id');
  const result = await c.env.DB.prepare(
    "UPDATE books SET deleted_at = datetime('now') WHERE id = ? AND deleted_at IS NULL"
  )
    .bind(id)
    .run();
  if ((result.meta?.changes ?? 0) === 0) return c.json({ error: 'Not found' }, 404);
  return c.json({ ok: true });
});

// One-off maintenance action: for EPUBs already uploaded before cover
// auto-extraction existed, try pulling their embedded cover now. Safe to
// call repeatedly — only touches books with format='epub' and cover_key
// still null, and any book whose EPUB doesn't declare a cover is simply
// left alone (not an error).
app.post('/admin/books/backfill-covers', requireAuth, requireAdmin, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT id, file_key FROM books WHERE format = 'epub' AND cover_key IS NULL AND deleted_at IS NULL`
  ).all<{ id: string; file_key: string }>();

  let updated = 0;
  const failed: string[] = [];

  for (const book of results) {
    try {
      const object = await c.env.FILES.get(book.file_key);
      if (!object) continue;
      const bytes = new Uint8Array(await object.arrayBuffer());
      const extracted = extractEpubCover(bytes);
      if (!extracted) continue;

      const ext = extracted.contentType === 'image/png' ? 'png' : 'jpg';
      const coverKey = `covers/${book.id}.${ext}`;
      await c.env.FILES.put(coverKey, extracted.bytes, { httpMetadata: { contentType: extracted.contentType } });
      await c.env.DB.prepare('UPDATE books SET cover_key = ? WHERE id = ?').bind(coverKey, book.id).run();
      updated++;
    } catch {
      failed.push(book.id);
    }
  }

  return c.json({ checked: results.length, updated, failed });
});

// ---------- Admin: shared helpers ----------
// D1 allows roughly 100 bound parameters per statement, so bulk requests are
// capped at 90 ids; the app splits bigger selections into several requests.
const MAX_BULK_IDS = 90;

function parseBulkIds(body: any): string[] | null {
  const ids = body?.ids;
  if (!Array.isArray(ids) || ids.length === 0 || ids.length > MAX_BULK_IDS) return null;
  if (!ids.every((i) => typeof i === 'string' && i.length > 0)) return null;
  return ids as string[];
}

function readPaging(c: any, defaultLimit = 60): { limit: number; offset: number } {
  const limitNum = parseInt(c.req.query('limit') ?? '', 10);
  const offsetNum = parseInt(c.req.query('offset') ?? '', 10);
  return {
    limit: Number.isFinite(limitNum) && limitNum > 0 ? Math.min(limitNum, MAX_BULK_IDS) : defaultLimit,
    offset: Number.isFinite(offsetNum) && offsetNum > 0 ? offsetNum : 0,
  };
}

// Permanently removes books. DB rows go first (children before parents, for
// the foreign keys), then the R2 files — so a failure part-way can only leave
// harmless orphaned files, never books whose files are gone.
async function hardDeleteBooks(env: Env, ids: string[]): Promise<number> {
  if (ids.length === 0) return 0;
  const ph = ids.map(() => '?').join(',');

  const { results } = await env.DB.prepare(`SELECT file_key, cover_key FROM books WHERE id IN (${ph})`)
    .bind(...ids)
    .all<{ file_key: string; cover_key: string | null }>();

  await env.DB.prepare(`DELETE FROM reading_progress WHERE book_id IN (${ph})`).bind(...ids).run();
  await env.DB.prepare(`DELETE FROM annotations WHERE book_id IN (${ph})`).bind(...ids).run();
  await env.DB.prepare(`DELETE FROM favorites WHERE book_id IN (${ph})`).bind(...ids).run();
  await env.DB.prepare(`DELETE FROM book_views WHERE book_id IN (${ph})`).bind(...ids).run();
  await env.DB.prepare(`DELETE FROM books WHERE id IN (${ph})`).bind(...ids).run();

  const keys: string[] = [];
  for (const r of results) {
    keys.push(r.file_key);
    if (r.cover_key) keys.push(r.cover_key);
  }
  if (keys.length > 0) await env.FILES.delete(keys);
  return results.length;
}

const BOOK_COLUMNS = 'id, title, author, description, format, cover_key, category, created_at';

// A book "needs attention" if anything an admin would want filled in is empty.
const NEEDS_ATTENTION_SQL =
  "(cover_key IS NULL OR author IS NULL OR TRIM(author) = '' OR category IS NULL OR TRIM(category) = '' OR description IS NULL OR TRIM(description) = '')";

// Groups of live books sharing the same title + author (ignoring case and
// surrounding spaces) — the same rule the edit screen enforces.
const DUPLICATE_GROUPS_SQL =
  "SELECT LOWER(TRIM(title)) AS t, LOWER(TRIM(COALESCE(author, ''))) AS a, COUNT(*) AS c FROM books WHERE deleted_at IS NULL GROUP BY t, a HAVING c > 1";

// ---------- Admin: trash, restore, bulk actions ----------

// "Delete" moves books to the trash: hidden from every reader, files and
// reading data kept, restorable for 30 days.
app.post('/admin/books/bulk-delete', requireAuth, requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null);
  const ids = parseBulkIds(body);
  if (!ids) return c.json({ error: `ids must be 1–${MAX_BULK_IDS} book ids` }, 400);
  const ph = ids.map(() => '?').join(',');

  const result = await c.env.DB.prepare(
    `UPDATE books SET deleted_at = datetime('now') WHERE deleted_at IS NULL AND id IN (${ph})`
  )
    .bind(...ids)
    .run();
  return c.json({ deleted: result.meta?.changes ?? 0 });
});

app.post('/admin/books/restore', requireAuth, requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null);
  const ids = parseBulkIds(body);
  if (!ids) return c.json({ error: `ids must be 1–${MAX_BULK_IDS} book ids` }, 400);
  const ph = ids.map(() => '?').join(',');

  const result = await c.env.DB.prepare(
    `UPDATE books SET deleted_at = NULL WHERE deleted_at IS NOT NULL AND id IN (${ph})`
  )
    .bind(...ids)
    .run();
  return c.json({ restored: result.meta?.changes ?? 0 });
});

// Permanently deletes books — only ones already in the trash.
app.post('/admin/books/purge', requireAuth, requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null);
  const ids = parseBulkIds(body);
  if (!ids) return c.json({ error: `ids must be 1–${MAX_BULK_IDS} book ids` }, 400);
  const ph = ids.map(() => '?').join(',');

  const { results } = await c.env.DB.prepare(`SELECT id FROM books WHERE deleted_at IS NOT NULL AND id IN (${ph})`)
    .bind(...ids)
    .all<{ id: string }>();
  const purged = await hardDeleteBooks(c.env, results.map((r) => r.id));
  return c.json({ purged });
});

// Set the same category on many books at once.
app.post('/admin/books/bulk-category', requireAuth, requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null);
  const ids = parseBulkIds(body);
  const category = typeof body?.category === 'string' ? body.category.trim() : '';
  if (!ids || !category) return c.json({ error: `category and 1–${MAX_BULK_IDS} ids are required` }, 400);
  const ph = ids.map(() => '?').join(',');

  await c.env.DB.prepare(`UPDATE books SET category = ? WHERE deleted_at IS NULL AND id IN (${ph})`)
    .bind(category, ...ids)
    .run();
  return c.json({ updated: ids.length });
});

// The trash. Anything in it for more than 30 days is permanently removed
// first (done here, on demand, so no scheduled job is needed).
app.get('/admin/trash', requireAuth, requireAdmin, async (c) => {
  for (let i = 0; i < 5; i++) {
    const { results } = await c.env.DB.prepare(
      "SELECT id FROM books WHERE deleted_at IS NOT NULL AND deleted_at < datetime('now', '-30 days') LIMIT ?"
    )
      .bind(MAX_BULK_IDS)
      .all<{ id: string }>();
    if (results.length === 0) break;
    await hardDeleteBooks(c.env, results.map((r) => r.id));
  }

  const { offset } = readPaging(c);
  const { results } = await c.env.DB.prepare(
    `SELECT id, title, author, format, deleted_at, datetime(deleted_at, '+30 days') AS expires_at
     FROM books WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC, id ASC LIMIT 100 OFFSET ?`
  )
    .bind(offset)
    .all();
  const countRow = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM books WHERE deleted_at IS NOT NULL').first<{ n: number }>();
  return c.json({ items: results, total: countRow?.n ?? results.length });
});

// Empties the trash a batch at a time; the app calls it until `remaining` is 0.
app.post('/admin/trash/empty', requireAuth, requireAdmin, async (c) => {
  const { results } = await c.env.DB.prepare('SELECT id FROM books WHERE deleted_at IS NOT NULL LIMIT ?')
    .bind(MAX_BULK_IDS)
    .all<{ id: string }>();
  const purged = await hardDeleteBooks(c.env, results.map((r) => r.id));
  const remainingRow = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM books WHERE deleted_at IS NOT NULL').first<{ n: number }>();
  return c.json({ purged, remaining: remainingRow?.n ?? 0 });
});

// ---------- Admin: the book list (server-side filter, search, paging) ----------
//   filter  all | needs (missing cover/author/category/description) | duplicates
//   q       title/author search     limit/offset   paging
//   idsOnly=1  returns every matching id (for "select all N matching")
app.get('/admin/books', requireAuth, requireAdmin, async (c) => {
  const filter = c.req.query('filter') ?? 'all';
  const q = c.req.query('q')?.trim().toLowerCase();
  const idsOnly = c.req.query('idsOnly') === '1';
  const { limit, offset } = readPaging(c);

  const where: string[] = ['deleted_at IS NULL'];
  const params: unknown[] = [];
  if (q) {
    where.push('(LOWER(title) LIKE ? OR LOWER(author) LIKE ?)');
    params.push(`%${q}%`, `%${q}%`);
  }

  let from = 'books b';
  let extraSelect = '';
  let order = '(cover_key IS NOT NULL) ASC, created_at DESC, id ASC'; // no cover first
  if (filter === 'needs') {
    where.push(NEEDS_ATTENTION_SQL);
  } else if (filter === 'duplicates') {
    from = `books b JOIN (${DUPLICATE_GROUPS_SQL}) d ON LOWER(TRIM(b.title)) = d.t AND LOWER(TRIM(COALESCE(b.author, ''))) = d.a`;
    extraSelect = ', d.c AS dup_count';
    // Copies of one book sit together; within a group the one with a cover
    // (then the newest) comes first — that's the copy "select extras" keeps.
    order = 'd.t ASC, d.a ASC, (cover_key IS NULL) ASC, created_at DESC, id ASC';
  }
  const whereSql = where.join(' AND ');

  if (idsOnly) {
    const { results } = await c.env.DB.prepare(`SELECT id FROM ${from} WHERE ${whereSql} ORDER BY ${order} LIMIT 20000`)
      .bind(...params)
      .all<{ id: string }>();
    return c.json({ ids: results.map((r) => r.id) });
  }

  const { results } = await c.env.DB.prepare(
    `SELECT ${BOOK_COLUMNS}${extraSelect} FROM ${from} WHERE ${whereSql} ORDER BY ${order} LIMIT ? OFFSET ?`
  )
    .bind(...params, limit, offset)
    .all();
  const countRow = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM ${from} WHERE ${whereSql}`)
    .bind(...params)
    .first<{ n: number }>();
  return c.json({ books: results, total: countRow?.n ?? results.length });
});

// Counts for the filter chips, in one round trip.
app.get('/admin/books/summary', requireAuth, requireAdmin, async (c) => {
  const res = await c.env.DB.batch([
    c.env.DB.prepare('SELECT COUNT(*) AS n FROM books WHERE deleted_at IS NULL'),
    c.env.DB.prepare(`SELECT COUNT(*) AS n FROM books WHERE deleted_at IS NULL AND ${NEEDS_ATTENTION_SQL}`),
    c.env.DB.prepare(`SELECT COALESCE(SUM(c), 0) AS n FROM (${DUPLICATE_GROUPS_SQL})`),
    c.env.DB.prepare('SELECT COUNT(*) AS n FROM books WHERE deleted_at IS NOT NULL'),
  ]);
  const n = (i: number) => ((res[i].results?.[0] as any)?.n as number) ?? 0;
  return c.json({ total: n(0), needsAttention: n(1), duplicates: n(2), trashed: n(3) });
});

// Every duplicate except one copy per group (the one with a cover, else the
// newest) — what "Select extras" ticks.
app.get('/admin/books/duplicate-extras', requireAuth, requireAdmin, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT id FROM (
       SELECT id, ROW_NUMBER() OVER (
         PARTITION BY LOWER(TRIM(title)), LOWER(TRIM(COALESCE(author, '')))
         ORDER BY (cover_key IS NULL) ASC, created_at DESC, id ASC
       ) AS rn
       FROM books WHERE deleted_at IS NULL
     ) WHERE rn > 1 LIMIT 20000`
  ).all<{ id: string }>();
  return c.json({ ids: results.map((r) => r.id) });
});

// ---------- Admin: book metrics ----------
// Lightweight usage stats — two counters incremented in the routes above
// (view_count on open, search_hit_count on matching a text search).
// Top 100 only; "never used" books are listed separately below.
app.get('/admin/books/metrics', requireAuth, requireAdmin, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT id, title, author, cover_key, view_count, search_hit_count
     FROM books WHERE deleted_at IS NULL AND (view_count > 0 OR search_hit_count > 0)
     ORDER BY view_count DESC, search_hit_count DESC LIMIT 100`
  ).all();
  return c.json({ books: results });
});

// Books nobody has ever opened or found by searching — candidates to
// promote or retire. Same fields as /books, so the app can open them for editing.
app.get('/admin/books/inactive', requireAuth, requireAdmin, async (c) => {
  const { limit, offset } = readPaging(c);
  const cond = 'deleted_at IS NULL AND view_count = 0 AND search_hit_count = 0';
  const { results } = await c.env.DB.prepare(
    `SELECT ${BOOK_COLUMNS} FROM books WHERE ${cond} ORDER BY created_at DESC, id ASC LIMIT ? OFFSET ?`
  )
    .bind(limit, offset)
    .all();
  const countRow = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM books WHERE ${cond}`).first<{ n: number }>();
  return c.json({ books: results, total: countRow?.n ?? results.length });
});

// ---------- Admin: user management ----------
app.get('/admin/users', requireAuth, requireAdmin, async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT id, email, display_name, is_admin, is_disabled, created_at FROM users ORDER BY created_at DESC'
  ).all();
  return c.json({ users: results });
});

app.post('/admin/users/:id/disable', requireAuth, requireAdmin, async (c) => {
  const id = c.req.param('id');
  if (id === c.get('userId')) return c.json({ error: "You can't disable your own account." }, 400);
  await c.env.DB.prepare('UPDATE users SET is_disabled = 1 WHERE id = ?').bind(id).run();
  return c.json({ ok: true });
});

app.post('/admin/users/:id/enable', requireAuth, requireAdmin, async (c) => {
  await c.env.DB.prepare('UPDATE users SET is_disabled = 0 WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// Promote a reader to admin, or demote an admin. You can't change your own
// role, which guarantees there is always at least one admin.
app.post('/admin/users/:id/role', requireAuth, requireAdmin, async (c) => {
  const id = c.req.param('id');
  if (id === c.get('userId')) return c.json({ error: "You can't change your own role." }, 400);
  const body = await c.req.json().catch(() => null);
  if (typeof body?.isAdmin !== 'boolean') return c.json({ error: 'isAdmin (true/false) is required' }, 400);
  await c.env.DB.prepare('UPDATE users SET is_admin = ? WHERE id = ?').bind(body.isAdmin ? 1 : 0, id).run();
  return c.json({ ok: true });
});

// Permanently delete an account and everything personal to it.
app.delete('/admin/users/:id', requireAuth, requireAdmin, async (c) => {
  const id = c.req.param('id');
  if (id === c.get('userId')) return c.json({ error: "You can't delete your own account." }, 400);
  for (const table of ['reading_progress', 'annotations', 'favorites', 'feedback', 'book_views']) {
    await c.env.DB.prepare(`DELETE FROM ${table} WHERE user_id = ?`).bind(id).run();
  }
  await c.env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
  return c.json({ ok: true });
});

// ---------- Feedback ----------
app.post('/feedback', requireAuth, async (c) => {
  const body = await c.req.json<{ message?: string }>();
  const message = body.message?.trim();
  if (!message) return c.json({ error: 'message is required' }, 400);

  await c.env.DB.prepare('INSERT INTO feedback (id, user_id, message) VALUES (?, ?, ?)')
    .bind(crypto.randomUUID(), c.get('userId'), message)
    .run();
  return c.json({ ok: true });
});

app.get('/admin/feedback/unread', requireAuth, requireAdmin, async (c) => {
  const row = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM feedback WHERE status = 'new'").first<{ n: number }>();
  return c.json({ count: row?.n ?? 0 });
});

// Unhandled first: new, then read, then done.
app.get('/admin/feedback', requireAuth, requireAdmin, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT feedback.id, feedback.message, feedback.created_at, feedback.status, users.email AS user_email
     FROM feedback JOIN users ON users.id = feedback.user_id
     ORDER BY CASE feedback.status WHEN 'new' THEN 0 WHEN 'read' THEN 1 ELSE 2 END, feedback.created_at DESC`
  ).all();
  return c.json({ feedback: results });
});

app.patch('/admin/feedback/:id', requireAuth, requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null);
  const status = body?.status;
  if (!['new', 'read', 'done'].includes(status)) return c.json({ error: "status must be 'new', 'read' or 'done'" }, 400);
  await c.env.DB.prepare('UPDATE feedback SET status = ? WHERE id = ?').bind(status, c.req.param('id')).run();
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

// ---------- Favorites ----------
app.get('/favorites', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare('SELECT book_id FROM favorites WHERE user_id = ?')
    .bind(c.get('userId'))
    .all<{ book_id: string }>();
  return c.json({ bookIds: results.map((r) => r.book_id) });
});

app.post('/favorites/:bookId', requireAuth, async (c) => {
  await c.env.DB.prepare('INSERT OR IGNORE INTO favorites (user_id, book_id) VALUES (?, ?)')
    .bind(c.get('userId'), c.req.param('bookId'))
    .run();
  return c.json({ ok: true });
});

app.delete('/favorites/:bookId', requireAuth, async (c) => {
  await c.env.DB.prepare('DELETE FROM favorites WHERE user_id = ? AND book_id = ?')
    .bind(c.get('userId'), c.req.param('bookId'))
    .run();
  return c.json({ ok: true });
});

// ---------- Annotations (highlights, underlines, notes) ----------
// Personal to each user — never shared between readers of the same book.

app.get('/annotations/:bookId', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT id, type, color, cfi, page, selected_text, note, created_at
     FROM annotations WHERE user_id = ? AND book_id = ? ORDER BY created_at ASC`
  )
    .bind(c.get('userId'), c.req.param('bookId'))
    .all();
  return c.json({ annotations: results });
});

app.post('/annotations', requireAuth, async (c) => {
  const body = await c.req.json<{
    bookId: string;
    type: 'highlight' | 'underline' | 'note';
    color?: string;
    cfi?: string;
    page?: number;
    selectedText?: string;
    note?: string;
  }>();

  if (!body.bookId || !body.type) return c.json({ error: 'bookId and type are required' }, 400);
  if (!['highlight', 'underline', 'note'].includes(body.type)) return c.json({ error: 'invalid type' }, 400);

  const id = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO annotations (id, user_id, book_id, type, color, cfi, page, selected_text, note)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      c.get('userId'),
      body.bookId,
      body.type,
      body.color ?? null,
      body.cfi ?? null,
      body.page ?? null,
      body.selectedText ?? null,
      body.note ?? null
    )
    .run();

  return c.json({
    annotation: {
      id,
      type: body.type,
      color: body.color ?? null,
      cfi: body.cfi ?? null,
      page: body.page ?? null,
      selected_text: body.selectedText ?? null,
      note: body.note ?? null,
    },
  });
});

app.patch('/annotations/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT user_id FROM annotations WHERE id = ?')
    .bind(id)
    .first<{ user_id: string }>();
  if (!existing) return c.json({ error: 'Not found' }, 404);
  if (existing.user_id !== c.get('userId')) return c.json({ error: 'Forbidden' }, 403);

  const body = await c.req.json<{ color?: string; note?: string }>();
  await c.env.DB.prepare('UPDATE annotations SET color = COALESCE(?, color), note = COALESCE(?, note) WHERE id = ?')
    .bind(body.color ?? null, body.note ?? null, id)
    .run();

  return c.json({ ok: true });
});

app.delete('/annotations/:id', requireAuth, async (c) => {
  const id = c.req.param('id');
  const existing = await c.env.DB.prepare('SELECT user_id FROM annotations WHERE id = ?')
    .bind(id)
    .first<{ user_id: string }>();
  if (!existing) return c.json({ error: 'Not found' }, 404);
  if (existing.user_id !== c.get('userId')) return c.json({ error: 'Forbidden' }, 403);

  await c.env.DB.prepare('DELETE FROM annotations WHERE id = ?').bind(id).run();
  return c.json({ ok: true });
});

// ---------- Admin: dashboard ----------
// Everything is time-windowed to the last 7 days where it makes sense, which
// the lifetime counters on each book can't do — that's what the dated
// book_views log is for. Entries older than 90 days are pruned as we go.
app.get('/admin/dashboard', requireAuth, requireAdmin, async (c) => {
  c.executionCtx.waitUntil(
    c.env.DB.prepare("DELETE FROM book_views WHERE viewed_at < datetime('now', '-90 days')").run()
  );

  const res = await c.env.DB.batch([
    c.env.DB.prepare('SELECT COUNT(*) AS n FROM books WHERE deleted_at IS NULL'),
    c.env.DB.prepare('SELECT COUNT(*) AS n FROM users'),
    c.env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE created_at >= datetime('now', '-7 days')"),
    c.env.DB.prepare("SELECT COUNT(*) AS n FROM books WHERE deleted_at IS NULL AND created_at >= datetime('now', '-7 days')"),
    c.env.DB.prepare(
      "SELECT COUNT(*) AS n, COUNT(DISTINCT user_id) AS readers FROM book_views WHERE viewed_at >= datetime('now', '-7 days')"
    ),
    c.env.DB.prepare('SELECT COUNT(*) AS n FROM books WHERE deleted_at IS NOT NULL'),
    c.env.DB.prepare("SELECT COUNT(*) AS n FROM feedback WHERE status = 'new'"),
    c.env.DB.prepare('SELECT COUNT(*) AS n FROM books WHERE deleted_at IS NULL AND cover_key IS NULL'),
    c.env.DB.prepare(
      `SELECT b.id, b.title, b.author, COUNT(*) AS views
       FROM book_views v JOIN books b ON b.id = v.book_id
       WHERE v.viewed_at >= datetime('now', '-7 days') AND b.deleted_at IS NULL
       GROUP BY b.id ORDER BY views DESC, b.title ASC LIMIT 5`
    ),
  ]);
  const n = (i: number, field = 'n') => ((res[i].results?.[0] as any)?.[field] as number) ?? 0;

  return c.json({
    totalBooks: n(0),
    totalUsers: n(1),
    newUsers7d: n(2),
    newBooks7d: n(3),
    opens7d: n(4),
    activeReaders7d: n(4, 'readers'),
    trashed: n(5),
    feedbackUnread: n(6),
    missingCovers: n(7),
    topBooks7d: res[8].results ?? [],
  });
});

// ---------- Admin: orphaned file cleanup ----------
// Finds files in storage that no book points at any more (e.g. books deleted
// straight from the database). Works one page of ~500 files per call; the
// app loops until nextCursor is null, first as a dry run, then to delete.
// Files uploaded in the last 10 minutes are never touched — an upload writes
// the file before its database row, so a very recent file may simply be
// mid-upload rather than orphaned.
app.post('/admin/storage/orphans', requireAuth, requireAdmin, async (c) => {
  const body: any = await c.req.json().catch(() => null);
  const prefix = body?.prefix === 'covers/' ? 'covers/' : 'books/';
  const cursor = typeof body?.cursor === 'string' && body.cursor.length > 0 ? body.cursor : undefined;
  const doDelete = body?.delete === true;

  const listing = await c.env.FILES.list({ prefix, cursor, limit: 500 });
  const objects = listing.objects;

  // File names are "<prefix><bookId>.<ext>", so look up the books they name
  // and collect the exact keys those books still use.
  const idOf = (key: string) => key.slice(prefix.length).split('.')[0];
  const bookIds = [...new Set(objects.map((o) => idOf(o.key)))];
  const inUse = new Set<string>();
  for (let i = 0; i < bookIds.length; i += MAX_BULK_IDS) {
    const chunk = bookIds.slice(i, i + MAX_BULK_IDS);
    const ph = chunk.map(() => '?').join(',');
    const { results } = await c.env.DB.prepare(`SELECT file_key, cover_key FROM books WHERE id IN (${ph})`)
      .bind(...chunk)
      .all<{ file_key: string; cover_key: string | null }>();
    for (const r of results) {
      inUse.add(r.file_key);
      if (r.cover_key) inUse.add(r.cover_key);
    }
  }

  const cutoff = Date.now() - 10 * 60 * 1000;
  const orphans = objects.filter((o) => !inUse.has(o.key) && o.uploaded.getTime() < cutoff);
  const orphanBytes = orphans.reduce((sum, o) => sum + o.size, 0);
  if (doDelete && orphans.length > 0) await c.env.FILES.delete(orphans.map((o) => o.key));

  return c.json({
    prefix,
    scanned: objects.length,
    orphans: orphans.length,
    orphanBytes,
    deleted: doDelete ? orphans.length : 0,
    nextCursor: listing.truncated ? listing.cursor : null,
  });
});

// ---------- Announcement banner ----------
// One optional message shown at the top of Home. Publishing gives it a fresh
// id, so people who dismissed an older announcement see the new one.
app.get('/announcement', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT key, value FROM settings WHERE key IN ('announcement_text', 'announcement_id')"
  ).all<{ key: string; value: string }>();
  const map = new Map(results.map((r) => [r.key, r.value]));
  const text = map.get('announcement_text');
  if (!text) return c.json({ announcement: null });
  return c.json({ announcement: { id: map.get('announcement_id') ?? '0', text } });
});

app.put('/admin/announcement', requireAuth, requireAdmin, async (c) => {
  const body: any = await c.req.json().catch(() => null);
  const text = typeof body?.text === 'string' ? body.text.trim().slice(0, 300) : '';

  if (!text) {
    await c.env.DB.prepare("DELETE FROM settings WHERE key IN ('announcement_text', 'announcement_id')").run();
    return c.json({ ok: true, announcement: null });
  }
  const id = crypto.randomUUID();
  const upsert = 'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value';
  await c.env.DB.batch([
    c.env.DB.prepare(upsert).bind('announcement_text', text),
    c.env.DB.prepare(upsert).bind('announcement_id', id),
  ]);
  return c.json({ ok: true, announcement: { id, text } });
});

// ---------- Admin: export ----------
// The whole library as a CSV (a UTF-8 byte-order mark first, so Excel shows
// accented characters correctly) — a backup of the catalogue, not the files.
app.get('/admin/export/books.csv', requireAuth, requireAdmin, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT id, title, author, category, format, description, file_size,
            CASE WHEN cover_key IS NULL THEN 0 ELSE 1 END AS has_cover,
            view_count, search_hit_count, created_at
     FROM books WHERE deleted_at IS NULL ORDER BY created_at DESC, id ASC`
  ).all();

  const columns = [
    'id', 'title', 'author', 'category', 'format', 'description',
    'file_size', 'has_cover', 'view_count', 'search_hit_count', 'created_at',
  ];
  const cell = (value: unknown) => {
    const text = value === null || value === undefined ? '' : String(value);
    return /[",\r\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
  };
  const lines = [columns.join(',')];
  for (const row of results as any[]) lines.push(columns.map((k) => cell(row[k])).join(','));

  return new Response('\uFEFF' + lines.join('\r\n'), {
    headers: {
      'content-type': 'text/csv; charset=utf-8',
      'content-disposition': 'attachment; filename="ereader-books.csv"',
    },
  });
});

app.get('/', (c) => c.text('ereader API is running'));

export default app;
