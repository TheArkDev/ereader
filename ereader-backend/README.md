# ereader-backend

Cloudflare Worker API for the Flutter e-reader app. Uses **D1** (metadata),
**R2** (book files + covers), and **KV** (logout/token revocation — your
existing `ereader` namespace).

## 1. Install & log in

```bash
npm install
npx wrangler login
```

## 2. Create the D1 database

```bash
npx wrangler d1 create ereader-db
```

Copy the `database_id` it prints into `wrangler.jsonc` (`d1_databases[0].database_id`).

Then create the tables:

```bash
npm run db:init          # local dev database
npm run db:init:remote   # the real, deployed database
```

## 3. Create the R2 bucket

```bash
npx wrangler r2 bucket create ereader-files
```

(The bucket name in `wrangler.jsonc` already matches this.)

## 4. Set a real JWT secret

```bash
npx wrangler secret put JWT_SECRET
```
Paste a long random string when prompted. (The `dev-only-change-me` value
in `wrangler.jsonc` is only used for local `wrangler dev`.)

## 5. Run locally / deploy

```bash
npm run dev       # local dev server, http://localhost:8787
npm run deploy    # publish to your workers.dev / custom domain
```

## 6. Add a book

Upload the file and cover to R2, then insert a row in D1. Example for a PDF:

```bash
npx wrangler r2 object put ereader-files/books/dune.pdf --file=./dune.pdf --remote
npx wrangler r2 object put ereader-files/covers/dune.jpg --file=./dune-cover.jpg --remote

npx wrangler d1 execute ereader-db --remote --command \
  "INSERT INTO books (id, title, author, description, format, file_key, cover_key) VALUES ('$(uuidgen)', 'Dune', 'Frank Herbert', 'A desert planet, a young heir, a rebellion.', 'pdf', 'books/dune.pdf', 'covers/dune.jpg')"
```

Use `format` = `'epub'` and an `.epub` file for EPUB titles — the API serves
either one the same way.

## API summary

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/auth/signup` | – | `{ email, password, displayName? }` → `{ token, user }` |
| POST | `/auth/login` | – | `{ email, password }` → `{ token, user }` |
| POST | `/auth/logout` | ✓ | revokes the current token |
| GET | `/auth/me` | ✓ | current user |
| GET | `/books` | ✓ | list, newest first |
| GET | `/books/:id` | ✓ | one book's metadata |
| GET | `/books/:id/file` | ✓ | streams the pdf/epub (supports `Range`) |
| GET | `/books/:id/cover` | ✓ | streams the cover jpg |
| GET/PUT | `/progress/:bookId` | ✓ | resume position: `{ position }` |

All `✓` routes need `Authorization: Bearer <token>`.
