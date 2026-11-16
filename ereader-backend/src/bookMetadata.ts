import { inflateSync, strFromU8, unzipSync } from 'fflate';

// Reads a book's author, description and title from inside the file itself.
//
//  • EPUB: the package (.opf) file carries <dc:creator>, <dc:description>
//    and <dc:title> — usually accurate, because the publisher put them there.
//  • PDF: the "document information" dictionary (/Author /Title /Subject) and,
//    when present, the XMP block. Hit and miss: plenty of PDFs leave these
//    empty or fill them with the name of the program that made the file, so
//    junk like "Microsoft Word" or "admin" is filtered out.
//
// Everything here is plain functions on bytes, so it runs the same in the
// Worker and in a test.

/** Where a description came from: the file's own field (trustworthy), a page
 *  in the book that is the blurb, or just the book's opening text (a stand-in). */
export type DescriptionSource = 'metadata' | 'blurb' | 'opening';

export interface FileMetadata {
  author?: string;
  description?: string;
  descriptionSource?: DescriptionSource;
  title?: string;
}

export type Confidence = 'high' | 'medium' | 'low';

// ---------- cleaning ----------

const JUNK_AUTHORS = new Set([
  'admin', 'administrator', 'user', 'owner', 'author', 'authors', 'unknown', 'na', 'n/a', 'none',
  'null', 'nil', 'test', 'default', 'pc', 'computer', 'windows user', 'system', 'home', 'office',
  'publisher', 'your name', 'name', 'untitled', 'anonymous', 'anonymous user',
]);

const SOFTWARE_NAMES =
  /\b(microsoft|adobe|acrobat|word|libreoffice|openoffice|pdf ?creator|scanner|calibre|indesign|quark(?:xpress)?|distiller|ghostscript|canva|google docs|kindle|writer|pages|latex|pdftex|wkhtmltopdf)\b/i;

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', rsquo: '\u2019', lsquo: '\u2018',
  rdquo: '\u201d', ldquo: '\u201c', ndash: '\u2013', mdash: '\u2014', hellip: '\u2026',
};

function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (whole, body: string) => {
    if (body[0] === '#') {
      const code = body[1].toLowerCase() === 'x' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : whole;
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? whole;
  });
}

/** Markup in, plain text out (also unwraps CDATA and entity-escaped markup). */
function htmlToText(raw: string): string {
  let t = raw.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
  t = decodeEntities(t); // metadata is often HTML that was escaped as &lt;p&gt;…
  t = t.replace(/<br\s*\/?>|<\/p>|<\/div>|<\/li>/gi, '\n');
  t = t.replace(/<[^>]+>/g, '');
  t = decodeEntities(t);
  return t.replace(/[ \t\u00a0]+/g, ' ').replace(/\s*\n\s*/g, '\n').trim();
}

/** A usable author name, or undefined if the value is empty, a placeholder,
 *  or the name of software / a username rather than a person. */
export function cleanAuthor(raw: string | undefined | null): string | undefined {
  if (!raw) return undefined;
  let a = htmlToText(raw).replace(/\s+/g, ' ').trim();
  if (a.length < 3 || a.length > 120) return undefined;
  if (JUNK_AUTHORS.has(a.toLowerCase())) return undefined;
  if (/@|https?:\/\/|www\./i.test(a)) return undefined;
  if (/\.(docx?|pdf|epub|indd|qxd|pub|tmp|txt)\b/i.test(a)) return undefined;
  if (SOFTWARE_NAMES.test(a)) return undefined;
  if (!/\p{L}/u.test(a)) return undefined;

  // "Sanders, J. Oswald" -> "J. Oswald Sanders" (but leave "Smith, Jr." and lists alone)
  const flipped = a.match(/^([^,;&]+),\s*([^,;&]+)$/);
  if (flipped && !/\b(jr|sr|ii|iii|iv|phd|md|dd)\.?$/i.test(flipped[2].trim()) && !/\band\b/i.test(a)) {
    a = `${flipped[2].trim()} ${flipped[1].trim()}`;
  }
  return a;
}

// Compared with case, dots, slashes and spaces removed, so "N/A", "n.a." and "Not Available" are all caught.
const PLACEHOLDER_TEXT = new Set([
  'na', 'none', 'null', 'nil', '-', '--', '\u2013', '\u2014', 'unknown', 'notavailable', 'notapplicable', 'tbd',
  'nodescription', 'nodescriptionavailable', 'descriptionnotavailable', 'nodata',
]);

/** A tidy description, or undefined if it's missing, a placeholder, or too short to mean anything. */
export function cleanDescription(raw: string | undefined | null, title?: string): string | undefined {
  if (!raw) return undefined;
  let t = htmlToText(raw);
  if (t.length < 40) return undefined;
  if (PLACEHOLDER_TEXT.has(t.toLowerCase().replace(/[.\/\s]/g, ''))) return undefined;
  if (/^(https?:\/\/|www\.)\S+$/i.test(t)) return undefined;
  if (title && t.toLowerCase() === title.trim().toLowerCase()) return undefined;

  return capAtSentence(t, 1500, 500);
}

/** Shortens [text] to about [max] characters, ending on a full sentence when it can. */
function capAtSentence(text: string, max: number, minEnd: number): string {
  if (text.length <= max) return text;
  const window = text.slice(0, max);
  const end = Math.max(window.lastIndexOf('. '), window.lastIndexOf('! '), window.lastIndexOf('? '));
  return end > minEnd ? window.slice(0, end + 1) : window.trimEnd() + '\u2026';
}

/** A title worth comparing against, or undefined for placeholder titles that
 *  software leaves behind ("Untitled", "Document1", "Microsoft Word - …"). */
export function cleanTitle(raw: string | undefined | null): string | undefined {
  if (!raw) return undefined;
  const t = htmlToText(raw).replace(/\s+/g, ' ').trim();
  if (t.length < 2) return undefined;
  if (/^(untitled|new document|document ?\d*|slide ?\d*|presentation ?\d*|book ?\d+)$/i.test(t)) return undefined;
  if (/^microsoft (word|powerpoint|excel)\b/i.test(t)) return undefined;
  if (/\.(docx?|pdf|epub|indd|qxd|pub|tmp|txt)$/i.test(t)) return undefined;
  return t;
}

// ---------- comparing with the library's own title ----------

const STOP_WORDS = new Set(['the', 'and', 'for', 'with', 'from', 'your', 'you', 'of', 'to', 'in', 'a', 'an', 'on', 'by']);

function titleTokens(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of text.toLowerCase().split(/[^\p{L}\p{N}]+/u)) {
    if (raw.length < 3 || STOP_WORDS.has(raw)) continue;
    out.add(raw.length > 4 && raw.endsWith('s') && !raw.endsWith('ss') ? raw.slice(0, -1) : raw);
  }
  return out;
}

/** Does the title stored *inside* the file agree with the title in the library? */
export function titleRelation(libraryTitle: string, fileTitle?: string): 'match' | 'mismatch' | 'none' {
  if (!fileTitle) return 'none';
  const a = titleTokens(libraryTitle);
  const b = titleTokens(fileTitle);
  if (a.size === 0 || b.size === 0) return 'none';
  let shared = 0;
  for (const token of a) if (b.has(token)) shared++;
  return shared / Math.min(a.size, b.size) >= 0.5 ? 'match' : 'mismatch';
}

/** How far to trust what was read. A PDF whose embedded title disagrees with
 *  the book's title probably carries leftover metadata from a template. */
export function confidenceFor(format: 'epub' | 'pdf', relation: 'match' | 'mismatch' | 'none'): Confidence {
  if (format === 'epub') return relation === 'mismatch' ? 'medium' : 'high';
  if (relation === 'match') return 'high';
  return relation === 'none' ? 'medium' : 'low';
}

// ---------- is the library's title right? ----------

export type TitleVerdict = 'match' | 'better' | 'conflict' | 'none';

export interface TitleAssessment {
  verdict: TitleVerdict;
  /** The title from the file, tidied — present for 'better' and 'conflict'. */
  proposed?: string;
  confidence?: Confidence;
  reason?: string;
}

// Words that show up when a title was made from a download filename.
const JUNKY_TITLE = /\b(z-?lib(?:rary)?|libgen|pdfdrive|scribd|torrent|ebook|e-book|epub|pdf|mobi|azw3?|scan(?:ned)?|ocr|www|copy of)\b|\.(com|org|net)\b|\([^)]*\)|\[[^\]]*\]|_/i;

/** "THE SCREWTAPE LETTERS" -> "The Screwtape Letters". Only touches titles that are shouted. */
function tidyCase(title: string): string {
  const letters = title.replace(/[^\p{L}]/gu, '');
  if (letters.length < 4) return title;
  const upper = letters.replace(/[^\p{Lu}]/gu, '').length;
  if (upper / letters.length < 0.9) return title;
  const small = new Set(['a', 'an', 'the', 'and', 'or', 'of', 'in', 'on', 'to', 'for', 'at', 'by', 'with']);
  return title
    .toLowerCase()
    .split(/(\s+)/)
    .map((part, i) => (/\s+/.test(part) || part === '' ? part : i > 0 && small.has(part) ? part : part[0].toUpperCase() + part.slice(1)))
    .join('');
}

/** Compares the title the library holds with the title written inside the file,
 *  and says whether to leave it, replace it, or let a person decide. */
export function assessTitle(libraryTitle: string, fileTitleRaw: string | undefined): TitleAssessment {
  const fileTitle = cleanTitle(fileTitleRaw);
  if (!fileTitle) return { verdict: 'none' };

  const library = libraryTitle.trim();
  const a = titleTokens(library);
  const b = titleTokens(fileTitle);
  if (a.size === 0 || b.size === 0) return { verdict: 'none' };

  const libraryInFile = [...a].every((t) => b.has(t)); // the library's words are all in the file's title
  const fileInLibrary = [...b].every((t) => a.has(t)); // the file's words are all in the library's title
  const junky = JUNKY_TITLE.test(library);
  const proposed = tidyCase(fileTitle.replace(/\s+/g, ' ').trim());

  // Same words (case, punctuation, "the" aside), or the library holds the main title
  // and the file adds a subtitle: the library's title is fine.
  if (libraryInFile) return { verdict: 'match' };

  // The library's title has extra words (a filename leftover, the author's name…)
  // around what the file says. Don't shorten a title to a single word, though —
  // that's more likely the main title of a longer one — unless it's clearly junk.
  if (fileInLibrary) {
    if (b.size < 2 && !junky) return { verdict: 'match' };
    return junky
      ? { verdict: 'better', proposed, confidence: 'high', reason: 'The current title looks like a download filename' }
      : { verdict: 'better', proposed, confidence: 'medium', reason: 'The current title has extra words the book itself doesn\'t' };
  }

  let shared = 0;
  for (const t of a) if (b.has(t)) shared++;
  const overlap = shared / Math.min(a.size, b.size);
  if (overlap >= 0.5) {
    return { verdict: 'conflict', proposed, confidence: junky ? 'medium' : 'low', reason: 'The wording differs — check which is right' };
  }
  return {
    verdict: 'conflict',
    proposed,
    confidence: 'low',
    reason: 'The title inside the file is quite different — it may be leftover from another book, or the wrong file',
  };
}

// ---------- EPUB ----------

function firstTag(xml: string, name: string): string | undefined {
  const m = new RegExp(`<(?:\\w+:)?${name}\\b[^>]*>([\\s\\S]*?)</(?:\\w+:)?${name}>`, 'i').exec(xml);
  return m?.[1];
}

/** Author / description / title from the text of an EPUB's package (.opf) file. */
export function parseEpubPackage(xml: string): FileMetadata {
  const metadata = /<(?:\w+:)?metadata\b[\s\S]*?<\/(?:\w+:)?metadata>/i.exec(xml)?.[0] ?? xml;

  // EPUB 3 can label each creator's role (author, translator, illustrator…) in
  // separate <meta refines="#id" property="role"> entries; EPUB 2 uses opf:role.
  const roles = new Map<string, string>();
  for (const m of metadata.matchAll(/<meta\b[^>]*refines\s*=\s*["']#([^"']+)["'][^>]*property\s*=\s*["']role["'][^>]*>([^<]*)</gi)) {
    roles.set(m[1], m[2].trim().toLowerCase());
  }

  const authors: string[] = [];
  for (const m of metadata.matchAll(/<(?:\w+:)?creator\b([^>]*)>([\s\S]*?)<\/(?:\w+:)?creator>/gi)) {
    const attrs = m[1];
    const id = /\bid\s*=\s*["']([^"']+)["']/i.exec(attrs)?.[1];
    const role = (/\brole\s*=\s*["']([^"']+)["']/i.exec(attrs)?.[1] ?? (id ? roles.get(id) : undefined))?.toLowerCase();
    if (role && role !== 'aut') continue; // skip translators, illustrators, editors…
    const name = cleanAuthor(m[2]);
    if (name && !authors.includes(name)) authors.push(name);
  }

  const rawTitle = firstTag(metadata, 'title');
  const title = rawTitle ? cleanTitle(rawTitle) : undefined;
  const result: FileMetadata = {};
  if (authors.length > 0) result.author = authors.slice(0, 3).join(', ');
  const description = cleanDescription(firstTag(metadata, 'description'), title);
  if (description) {
    result.description = description;
    result.descriptionSource = 'metadata';
  }
  if (title) result.title = title;
  return result;
}

function opfPathFromContainer(containerXml: string): string | undefined {
  return /full-path\s*=\s*["']([^"']+)["']/i.exec(containerXml)?.[1];
}

/** Reads an EPUB that's already fully in memory. Fine for small files and tests;
 *  the Worker uses {@link readEpubMetadataRanged} so big books never get loaded. */
export function readEpubMetadata(bytes: Uint8Array): FileMetadata {
  // Only inflate the two tiny files we need, not the whole book.
  const files = unzipSync(bytes, {
    filter: (file) => file.name === 'META-INF/container.xml' || file.name.toLowerCase().endsWith('.opf'),
  });

  let opfBytes: Uint8Array | undefined;
  const container = files['META-INF/container.xml'];
  if (container) {
    const path = opfPathFromContainer(strFromU8(container));
    if (path) opfBytes = files[path] ?? files[decodeURIComponent(path)];
  }
  if (!opfBytes) {
    const anyOpf = Object.keys(files).find((name) => name.toLowerCase().endsWith('.opf'));
    if (anyOpf) opfBytes = files[anyOpf];
  }
  return opfBytes ? parseEpubPackage(strFromU8(opfBytes)) : {};
}

// ----- reading an EPUB without loading it -----
//
// A zip file keeps an index (the "central directory") at its very end. So to
// find the two small files we want we read the last 256 KB of the book, locate
// them in the index, and fetch just those bytes — a few hundred KB however big
// the EPUB is. Loading a 40 MB EPUB whole is what pushes a Worker over its
// CPU/memory limit and makes Cloudflare answer "503".

export interface RangedSource {
  /** Total size of the file in bytes. */
  size: number;
  /** The bytes from `offset` for `length` (fewer if the file ends first). */
  read(offset: number, length: number): Promise<Uint8Array>;
}

interface ZipEntry {
  name: string;
  nameLength: number;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
}

const MAX_METADATA_FILE = 3 * 1024 * 1024; // an .opf is a few KB; refuse anything absurd
const MAX_ZIP_INDEX = 8 * 1024 * 1024;
const TAIL_BYTES = 256 * 1024;

async function readZipEntry(source: RangedSource, entry: ZipEntry, maxSize = MAX_METADATA_FILE): Promise<Uint8Array> {
  if (entry.compressedSize > maxSize || entry.uncompressedSize > maxSize) {
    throw new Error(`${entry.name} is unexpectedly large`);
  }
  // One read normally covers the entry's local header and its data. The local
  // header's own name/extra lengths can differ a little from the index's, hence the slack.
  const chunk = await source.read(entry.localOffset, 30 + entry.nameLength + 1024 + entry.compressedSize);
  if (chunk.length < 30) throw new Error('Corrupt zip entry');
  const view = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  if (view.getUint32(0, true) !== 0x04034b50) throw new Error('Corrupt zip entry header');

  const dataStart = 30 + view.getUint16(26, true) + view.getUint16(28, true);
  const data =
    dataStart + entry.compressedSize <= chunk.length
      ? chunk.subarray(dataStart, dataStart + entry.compressedSize)
      : await source.read(entry.localOffset + dataStart, entry.compressedSize);
  if (data.length < entry.compressedSize) throw new Error('Truncated zip entry');

  if (entry.method === 0) return data; // stored
  if (entry.method === 8) return inflateSync(data); // deflated
  throw new Error(`Unsupported zip compression (${entry.method})`);
}

/** Walks the zip index, keeping the entries [want] accepts (judged from the raw name bytes). */
function scanZipIndex(index: Uint8Array, want: (nameStart: number, nameEnd: number) => boolean): Map<string, ZipEntry> {
  const found = new Map<string, ZipEntry>();
  const iv = new DataView(index.buffer, index.byteOffset, index.byteLength);
  let p = 0;
  while (p + 46 <= index.length && iv.getUint32(p, true) === 0x02014b50) {
    const nameLength = iv.getUint16(p + 28, true);
    const extraLength = iv.getUint16(p + 30, true);
    const commentLength = iv.getUint16(p + 32, true);
    const nameStart = p + 46;
    const nameEnd = nameStart + nameLength;
    if (want(nameStart, nameEnd)) {
      const name = strFromU8(index.subarray(nameStart, nameEnd));
      found.set(name, {
        name,
        nameLength,
        method: iv.getUint16(p + 10, true),
        compressedSize: iv.getUint32(p + 20, true),
        uncompressedSize: iv.getUint32(p + 24, true),
        localOffset: iv.getUint32(p + 42, true),
      });
    }
    p += 46 + nameLength + extraLength + commentLength;
  }
  return found;
}

// ----- finding a description when the file has no description field -----

// A book page that IS the blurb ("About the Book", "Description", "Back cover"…).
const BLURB_PAGE = /(^|[\/_\-. ])(description|blurb|about[-_ ]?the[-_ ]?book|synopsis|overview|summary|back[-_ ]?cover|jacket|promo)([\/_\-. ]|$)/i;
// Pages that are never prose worth quoting.
const NOT_PROSE_PAGE = /(cover|title|copyright|toc|nav|contents|dedicat|acknowledg|epigraph|halftitle|colophon|praise|also-?by|about-?the-?author|author|permissions|imprint)/i;
// Paragraph content that marks front/back matter.
const FRONT_MATTER_TEXT = /(copyright|all rights reserved|isbn|published by|library of congress|printed in|first (?:edition|printing)|scripture quotations|permission|dedicat|acknowledg|table of contents|www\.|https?:|\bpraise for\b|about the author)/i;

const MAX_PROSE_FILE = 400 * 1024; // of *uncompressed* text — bigger chapters are skipped, not inflated
const MAX_PAGES_READ = 5;

/** An XHTML page as plain text, one paragraph per line. */
function xhtmlToText(html: string): string {
  let t = html.replace(/<head\b[\s\S]*?<\/head>/gi, ' ').replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, ' ');
  t = t.replace(/<\/(p|div|h[1-6]|li|blockquote|tr|section)>|<br\s*\/?>/gi, '\n');
  t = t.replace(/<[^>]+>/g, '');
  t = decodeEntities(t);
  return t.replace(/[ \t\u00a0]+/g, ' ').replace(/\s*\n\s*/g, '\n').trim();
}

/** Drops heading-like lines (short, no closing punctuation) from the top of a page's text. */
function withoutLeadingHeadings(text: string): string {
  const lines = text.split('\n');
  while (lines.length > 0 && lines[0].trim().length < 60 && !/[.!?:]["'\u201d\u2019)]?$/.test(lines[0].trim())) lines.shift();
  return lines.join('\n').trim();
}

/** Paragraphs that read like the book's own prose (not headings, credits or lists). */
function proseParagraphs(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split('\n')) {
    const p = raw.trim();
    if (p.length < 140 || p.length > 1500) continue;
    if (!/[.!?]["'\u201d\u2019)\]]?$/.test(p)) continue;
    if ((p.match(/[.!?](?:\s|$)/g)?.length ?? 0) < 2) continue;
    if (FRONT_MATTER_TEXT.test(p)) continue;
    if ((p.match(/\p{L}/gu)?.length ?? 0) / p.length < 0.75) continue;
    out.push(p);
  }
  return out;
}

function attrOf(attrs: string, name: string): string | undefined {
  return new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, 'i').exec(attrs)?.[1];
}

function resolveZipPath(dir: string, href: string): string {
  let clean = href.split('#')[0];
  try {
    clean = decodeURIComponent(clean);
  } catch {
    // keep it as written
  }
  const out: string[] = [];
  for (const part of (dir + clean).split('/')) {
    if (part === '..') out.pop();
    else if (part !== '.' && part !== '') out.push(part);
  }
  return out.join('/');
}

/** The book's reading order: [{id, path}] for each XHTML page in the spine. */
function spinePages(opfXml: string, opfPath: string): Array<{ id: string; path: string }> {
  const manifest = new Map<string, { href: string; type: string }>();
  for (const m of opfXml.matchAll(/<item\b([^>]*)>/gi)) {
    const id = attrOf(m[1], 'id');
    const href = attrOf(m[1], 'href');
    if (id && href) manifest.set(id, { href, type: attrOf(m[1], 'media-type') ?? '' });
  }
  const dir = opfPath.includes('/') ? opfPath.slice(0, opfPath.lastIndexOf('/') + 1) : '';
  const pages: Array<{ id: string; path: string }> = [];
  for (const m of opfXml.matchAll(/<itemref\b([^>]*)>/gi)) {
    const idref = attrOf(m[1], 'idref');
    if (!idref || /\blinear\s*=\s*["']no["']/i.test(m[1])) continue; // skip non-linear extras (usually the cover)
    const item = manifest.get(idref);
    if (!item) continue;
    if (!/x?html/i.test(item.type) && !/\.x?html?$/i.test(item.href)) continue;
    pages.push({ id: idref, path: resolveZipPath(dir, item.href) });
  }
  return pages;
}

/** Looks inside the book for something that can stand in for a description:
 *  first a page that is the blurb, otherwise the opening paragraphs of its prose. */
async function descriptionFromContent(
  source: RangedSource,
  index: Uint8Array,
  opfXml: string,
  opfPath: string,
  title: string | undefined,
): Promise<{ text: string; source: DescriptionSource } | undefined> {
  const pages = spinePages(opfXml, opfPath).slice(0, 60);
  if (pages.length === 0) return undefined;
  const entries = scanZipIndex(index, () => true); // names of every file, so spine paths can be looked up

  const readPage = async (path: string): Promise<string | undefined> => {
    const entry = entries.get(path);
    if (!entry || entry.uncompressedSize > MAX_PROSE_FILE) return undefined;
    try {
      return xhtmlToText(strFromU8(await readZipEntry(source, entry, MAX_PROSE_FILE)));
    } catch {
      return undefined;
    }
  };

  // 1) a page that is the blurb
  let blurbsRead = 0;
  for (const page of pages) {
    if (blurbsRead >= 3) break;
    if (!BLURB_PAGE.test(page.path) && !BLURB_PAGE.test(page.id)) continue;
    blurbsRead++;
    const text = await readPage(page.path);
    if (!text || /about the author|praise for|table of contents/i.test(text)) continue;
    const cleaned = cleanDescription(withoutLeadingHeadings(text), title);
    if (cleaned) return { text: cleaned, source: 'blurb' };
  }

  // 2) the opening paragraphs of real prose
  const paragraphs: string[] = [];
  let pagesRead = 0;
  for (const page of pages) {
    if (pagesRead >= MAX_PAGES_READ) break;
    const entry = entries.get(page.path);
    if (!entry || entry.uncompressedSize < 300 || entry.uncompressedSize > MAX_PROSE_FILE) continue;
    if (NOT_PROSE_PAGE.test(page.path) || NOT_PROSE_PAGE.test(page.id)) continue;
    pagesRead++;
    const text = await readPage(page.path);
    if (!text) continue;
    for (const p of proseParagraphs(text)) {
      paragraphs.push(p);
      if (paragraphs.join('\n').length >= 300) break;
    }
    if (paragraphs.join('\n').length >= 300) break;
  }
  if (paragraphs.length === 0) return undefined;
  return { text: capAtSentence(paragraphs.join('\n'), 700, 250), source: 'opening' };
}

export async function readEpubMetadataRanged(source: RangedSource, options: { deep?: boolean } = {}): Promise<FileMetadata> {
  if (source.size < 22) throw new Error('Not a valid EPUB (too small)');

  const tailLength = Math.min(source.size, TAIL_BYTES);
  const tailStart = source.size - tailLength;
  const tail = await source.read(tailStart, tailLength);

  // The "end of central directory" record: signature PK\x05\x06, within the last 64 KB + 22.
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0 && i >= tail.length - 22 - 65535; i--) {
    if (tail[i] === 0x50 && tail[i + 1] === 0x4b && tail[i + 2] === 0x05 && tail[i + 3] === 0x06) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('Not a valid EPUB (no zip index)');

  const tv = new DataView(tail.buffer, tail.byteOffset, tail.byteLength);
  const entryCount = tv.getUint16(eocd + 10, true);
  const indexSize = tv.getUint32(eocd + 12, true);
  const indexOffset = tv.getUint32(eocd + 16, true);
  if (entryCount === 0xffff || indexSize === 0xffffffff || indexOffset === 0xffffffff) {
    throw new Error('ZIP64 archives are not supported');
  }
  if (indexSize > MAX_ZIP_INDEX || indexOffset + indexSize > source.size) throw new Error('Corrupt zip index');

  const index =
    indexOffset >= tailStart
      ? tail.subarray(indexOffset - tailStart, indexOffset - tailStart + indexSize)
      : await source.read(indexOffset, indexSize);

  // An EPUB can hold thousands of entries; judge the raw name bytes and only turn
  // the two we want into strings (cheap — this runs inside a CPU-limited Worker).
  const wanted = scanZipIndex(index, (nameStart, nameEnd) => {
    const nameLength = nameEnd - nameStart;
    const isContainer = nameLength === 22 && strFromU8(index.subarray(nameStart, nameEnd)) === 'META-INF/container.xml';
    const isOpf =
      nameLength > 4 &&
      index[nameEnd - 4] === 0x2e && // "."
      (index[nameEnd - 3] | 0x20) === 0x6f && // o / O
      (index[nameEnd - 2] | 0x20) === 0x70 && // p / P
      (index[nameEnd - 1] | 0x20) === 0x66; // f / F
    return isContainer || isOpf;
  });

  let opfEntry: ZipEntry | undefined;
  const container = wanted.get('META-INF/container.xml');
  if (container) {
    const path = opfPathFromContainer(strFromU8(await readZipEntry(source, container)));
    if (path) opfEntry = wanted.get(path) ?? wanted.get(decodeURIComponent(path));
  }
  if (!opfEntry) opfEntry = [...wanted.values()].find((e) => e.name.toLowerCase().endsWith('.opf'));
  if (!opfEntry) return {};

  const opfXml = strFromU8(await readZipEntry(source, opfEntry));
  const result = parseEpubPackage(opfXml);

  if (options.deep && !result.description) {
    const found = await descriptionFromContent(source, index, opfXml, opfEntry.name, result.title);
    if (found) {
      result.description = found.text;
      result.descriptionSource = found.source;
    }
  }
  return result;
}

// ---------- PDF ----------

function latin1(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 8192) out += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return out;
}

function decodePdfText(bytes: number[]): string {
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    let s = '';
    for (let i = 2; i + 1 < bytes.length; i += 2) s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    return s;
  }
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    let s = '';
    for (let i = 2; i + 1 < bytes.length; i += 2) s += String.fromCharCode((bytes[i + 1] << 8) | bytes[i]);
    return s;
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return new TextDecoder('utf-8').decode(new Uint8Array(bytes.slice(3)));
  }
  return String.fromCharCode(...bytes); // PDFDocEncoding is close enough to Latin-1 for names
}

/** The value of a /Key (literal) or /Key <hex> entry inside a PDF dictionary. */
function pdfString(dict: string, key: string): string | undefined {
  const start = new RegExp(`/${key}\\s*(\\(|<(?!<))`).exec(dict);
  if (!start) return undefined;
  let i = start.index + start[0].length;
  const bytes: number[] = [];

  if (start[1] === '<') {
    const end = dict.indexOf('>', i);
    if (end < 0) return undefined;
    let hex = dict.slice(i, end).replace(/\s+/g, '');
    if (hex.length % 2 === 1) hex += '0';
    for (let k = 0; k + 1 < hex.length; k += 2) {
      const value = parseInt(hex.slice(k, k + 2), 16);
      if (Number.isNaN(value)) return undefined;
      bytes.push(value);
    }
    return decodePdfText(bytes);
  }

  const escapes: Record<string, number> = { n: 10, r: 13, t: 9, b: 8, f: 12, '(': 40, ')': 41, '\\': 92 };
  let depth = 1;
  while (i < dict.length && depth > 0) {
    const ch = dict[i];
    if (ch === '\\') {
      const next = dict[i + 1];
      if (next === undefined) break;
      if (next >= '0' && next <= '7') {
        let octal = next;
        let j = i + 2;
        while (octal.length < 3 && j < dict.length && dict[j] >= '0' && dict[j] <= '7') octal += dict[j++];
        bytes.push(parseInt(octal, 8) & 0xff);
        i = j;
        continue;
      }
      if (next in escapes) bytes.push(escapes[next]);
      else if (next === '\r' || next === '\n') {
        if (next === '\r' && dict[i + 2] === '\n') i++; // a backslash at line end joins the lines
      } else bytes.push(next.charCodeAt(0) & 0xff);
      i += 2;
      continue;
    }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) break;
    }
    bytes.push(ch.charCodeAt(0) & 0xff);
    i++;
  }
  return decodePdfText(bytes);
}

/** The text of the document-information dictionary, wherever it lives in what we read. */
function findInfoDictionary(text: string): string | undefined {
  const ref = /\/Info\s+(\d+)\s+(\d+)\s+R/.exec(text);
  if (ref) {
    const obj = new RegExp(`(?:^|[\\s>])${ref[1]}\\s+${ref[2]}\\s+obj`).exec(text);
    if (obj) {
      const end = text.indexOf('endobj', obj.index);
      return text.slice(obj.index, end > 0 ? end : obj.index + 4000);
    }
  }
  // No usable reference: take the neighbourhood of the first /Author we can see.
  const author = text.indexOf('/Author');
  if (author >= 0) return text.slice(Math.max(0, author - 1000), author + 3000);
  return undefined;
}

/** First <rdf:li> text inside an XMP property like <dc:creator>. */
function xmpValue(text: string, property: string): string | undefined {
  const block = new RegExp(`<dc:${property}>([\\s\\S]*?)</dc:${property}>`, 'i').exec(text)?.[1];
  if (!block) return undefined;
  return /<rdf:li[^>]*>([\s\S]*?)<\/rdf:li>/i.exec(block)?.[1] ?? block;
}

/** [head] and [tail] are the first and last chunk of the PDF — the information
 *  dictionary sits near one end in almost every file, so there's no need to
 *  read the whole thing. */
export function readPdfMetadata(head: Uint8Array, tail?: Uint8Array): FileMetadata {
  const text = (tail ? latin1(tail) + '\n' : '') + latin1(head);
  const info = findInfoDictionary(text);

  const infoAuthor = info ? pdfString(info, 'Author') : undefined;
  const infoTitle = info ? pdfString(info, 'Title') : undefined;
  const infoSubject = info ? pdfString(info, 'Subject') : undefined;

  const xmpTitle = xmpValue(text, 'title');
  const title = cleanTitle(infoTitle) ?? cleanTitle(xmpTitle);

  const result: FileMetadata = {};
  const author = cleanAuthor(infoAuthor) ?? cleanAuthor(xmpValue(text, 'creator'));
  if (author) result.author = author;

  // A real description sometimes sits in XMP or in /Subject. /Subject is
  // usually just the title again, so it only counts when it's substantial.
  const description =
    cleanDescription(xmpValue(text, 'description'), title) ??
    (infoSubject && infoSubject.length >= 60 ? cleanDescription(infoSubject, title) : undefined);
  if (description) {
    result.description = description;
    result.descriptionSource = 'metadata';
  }
  if (title) result.title = title;
  return result;
}
